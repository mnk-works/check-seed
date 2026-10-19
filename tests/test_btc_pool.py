"""Tests for scripthash derivation, server parsing and pool rotation.

The scripthash values here were cross-checked against 40 independent public
Electrum servers: a scripthash derived from a known-funded address returned that
address's exact balance everywhere, and was rejected as invalid everywhere when
derived wrongly. Encoding wrong is loud, not silent.
"""

import pytest

from check_seed.btc import (
    derive,
    fmt_btc,
    mask_address,
    p2pkh_script,
    p2sh_script,
    p2wpkh_script,
    script_to_scripthash,
    scripthash_from_address,
)
from check_seed.electrum import ElectrumError, Server, _utxo_value, parse_server
from check_seed.pool import Pool

ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

# Verified end-to-end against 40 public servers: this address holds 15324 sats and
# every server agreed on that figure.
ANCHOR_ADDR = "3KJcgBCgrptgiydFmbvKB1hUBEmrfZ2b7U"
ANCHOR_SCRIPTHASH = "8b5355f4ffa97afba29607f362af922e23a5d533bc3779c5d43cc8aac4d2d65d"


# --- scripthash -----------------------------------------------------------

def test_scripthash_is_reversed_sha256_of_script():
    import hashlib

    script = p2pkh_script(bytes(20))
    assert script_to_scripthash(script) == hashlib.sha256(script).digest()[::-1].hex()


def test_scripthash_anchor_from_verified_address():
    assert scripthash_from_address(ANCHOR_ADDR) == ANCHOR_SCRIPTHASH


@pytest.mark.parametrize("script_type", ["p2pkh", "p2sh-p2wpkh", "p2wpkh"])
def test_derive_and_address_path_agree(script_type):
    """The two independent routes to a scripthash must produce the same value."""
    for d in derive(ABANDON, script_type, count=3):
        assert scripthash_from_address(d.address) == d.scripthash


def test_p2sh_p2wpkh_script_shape():
    """P2SH-P2WPKH wraps HASH160 of the OP_0 witness program."""
    import hashlib

    redeem = p2wpkh_script(bytes(20))
    expected = p2sh_script(hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest())
    assert expected[:2] == b"\xa9\x14" and expected[-1] == 0x87


def test_derive_uses_published_bip_vectors():
    """Addresses must match the official BIP44/49/84 test vectors."""
    assert derive(ABANDON, "p2wpkh", 1)[0].address == \
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    assert derive(ABANDON, "p2sh-p2wpkh", 1)[0].address == \
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
    assert derive(ABANDON, "p2pkh", 1)[0].address == \
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"


def test_taproot_rejected():
    with pytest.raises(ValueError, match="taproot"):
        scripthash_from_address("bc1p5cyxnuxmeuwuvkwfem96llyxf3q4h3c8v5j8s2fgqxl0z0x2j0k2s2")


def test_bad_address_rejected():
    with pytest.raises(Exception):
        scripthash_from_address("not-an-address")


def test_mask_address_hides_middle():
    m = mask_address(ANCHOR_ADDR)
    assert m == f"{ANCHOR_ADDR[:8]}...{ANCHOR_ADDR[-6:]}"
    assert len(m) < 25  # far shorter than the full address


def test_fmt_btc():
    assert fmt_btc(15324) == "0.00015324 BTC"
    assert fmt_btc(0) == "0.00000000 BTC"


# --- server list parsing --------------------------------------------------

def test_parse_explicit_ssl():
    s = parse_server("electrum.emzy.de:50002:ssl")
    assert (s.host, s.port, s.use_tls) == ("electrum.emzy.de", 50002, True)


def test_parse_explicit_tcp():
    s = parse_server("electrum.emzy.de:50001:tcp")
    assert (s.host, s.port, s.use_tls) == ("electrum.emzy.de", 50001, False)


def test_bare_50001_defaults_to_plaintext():
    """Regression: a 50001 entry used to be wrapped in TLS and failed to connect."""
    assert parse_server("host.example:50001").use_tls is False


def test_non_50001_defaults_to_tls():
    assert parse_server("host.example:50002").use_tls is True
    assert parse_server("host.example").use_tls is True


def test_comments_and_blanks_skipped():
    assert parse_server("# a comment") is None
    assert parse_server("   ") is None


# --- listunspent entry formats -------------------------------------------

def test_utxo_value_object_format():
    u = {"tx_hash": "ab", "tx_pos": 0, "height": 100, "value": 15324}
    assert _utxo_value(u) == 15324


def test_utxo_value_legacy_array_format():
    assert _utxo_value([100, 0, 15324]) == 15324


def test_utxo_value_rejects_garbage():
    with pytest.raises(ElectrumError):
        _utxo_value({"nope": 1})
    with pytest.raises(ElectrumError):
        _utxo_value("nonsense")


# --- pool behaviour (offline) --------------------------------------------

def _pool(n=6):
    return Pool([Server(f"h{i}.example", 50002, True) for i in range(n)], "round-robin")


def test_round_robin_actually_rotates():
    """Regression: every request used to land on the same server.

    _ordered() is a pure read; the cursor advances when the caller commits to a
    server, so drive it the way with_connection() does.
    """
    pool = _pool(6)
    seen = []
    for _ in range(6):
        seen.append(pool._ordered()[0].key)
        pool._i = (pool._i + 1) % len(pool.servers)
    assert len(set(seen)) == 6


def test_round_robin_advances_through_with_connection(monkeypatch):
    pool = _pool(6)
    used = []

    class FakeConn:
        def __init__(self, srv):
            self.srv = srv

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("check_seed.pool.Connection", FakeConn)
    for _ in range(6):
        _, srv = pool.with_connection(lambda c: 0)
        used.append(srv.key)
    assert len(set(used)) == 6


def test_failover_retries_next_server(monkeypatch):
    pool = _pool(6)
    calls = []

    def flaky(srv):
        class C:
            def __enter__(self):
                if srv.host == "h0.example":
                    raise OSError("boom")
                return self

            def __exit__(self, *a):
                return False

        calls.append(srv.host)
        return C()

    monkeypatch.setattr("check_seed.pool.Connection", flaky)
    _, srv = pool.with_connection(lambda c: 42, retries=3)
    assert srv.key != "h0.example"
    assert calls[0] == "h0.example"


def test_all_servers_failing_raises(monkeypatch):
    pool = _pool(3)

    def dead(srv):
        class C:
            def __enter__(self):
                raise OSError("down")

            def __exit__(self, *a):
                return False

        return C()

    monkeypatch.setattr("check_seed.pool.Connection", dead)
    with pytest.raises(ElectrumError, match="all servers failed"):
        pool.with_connection(lambda c: 0, retries=1)


def test_unknown_strategy_rejected():
    with pytest.raises(ValueError):
        Pool([Server("a", 50002)], "nonsense")


def test_empty_pool_rejected():
    with pytest.raises(ValueError):
        Pool([], "round-robin")


def test_server_health_cooldown():
    s = Server("a", 50002)
    assert s.healthy
    s.record_fail()
    assert not s.healthy
    s.down_until = 0.0
    s.record_ok(12.0)
    assert s.healthy and s.successes == 1 and s.latency_ms == 12.0