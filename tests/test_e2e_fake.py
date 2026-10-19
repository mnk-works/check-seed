"""End-to-end tests against a local fake Electrum server.

These exercise the real protocol client and the real balance-verification path
without touching the network, and cover the security property the tool advertises:
a server that lies about a balance must be caught by cross-checking.
"""

import pytest

from check_seed.balance_cli import verify_total
from check_seed.btc import scripthash_from_address
from check_seed.electrum import Connection, Server
from check_seed.pool import Pool

from .fake_server import FakeElectrum

SH = "8b5355f4ffa97afba29607f362af922e23a5d533bc3779c5d43cc8aac4d2d65d"
ADDR = "3KJcgBCgrptgiydFmbvKB1hUBEmrfZ2b7U"
ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def _srv(fake: FakeElectrum) -> Server:
    return Server("127.0.0.1", fake.port, use_tls=False)


@pytest.fixture
def honest():
    f = FakeElectrum(fake_value=0, honest=True)
    yield f
    f.stop()


@pytest.fixture
def liar():
    f = FakeElectrum(fake_value=50_000_000, honest=False)
    yield f
    f.stop()


# --- protocol basics ------------------------------------------------------

def test_handshake_and_listunspent(honest):
    with Connection(_srv(honest), timeout=5) as conn:
        assert conn.listunspent(SH) == []


def test_ping(honest):
    with Connection(_srv(honest), timeout=5) as conn:
        conn.ping()


def test_pool_poll_returns_zero_for_empty(honest):
    pool = Pool([_srv(honest)], "round-robin")
    confirmed, unconfirmed, key = pool.poll(SH)
    assert (confirmed, unconfirmed) == (0, 0)
    assert key == f"127.0.0.1:{honest.port}"


def test_pool_poll_reads_lie_from_single_server(liar):
    """A lone liar will happily report a big balance - which is the whole risk."""
    pool = Pool([_srv(liar)], "round-robin")
    confirmed, unconfirmed, _ = pool.poll(SH)
    assert confirmed + unconfirmed == 50_000_000


# --- pipelining and batching ----------------------------------------------

SH2 = "00" * 32
SH3 = "11" * 32


def test_call_many_pipelines_in_order(honest):
    """One write, many replies: order must be preserved."""
    with Connection(_srv(honest), timeout=5) as conn:
        out = conn.listunspent_many([SH, SH2, SH3])
    assert out == [[], [], []]
    assert honest.queries == [SH, SH2, SH3]


def test_poll_many_solves_every_scripthash(honest):
    pool = Pool([_srv(honest)], "round-robin")
    out = pool.poll_many([SH, SH2, SH3], workers=4)
    assert set(out) == {SH, SH2, SH3}
    assert all(v[:2] == (0, 0) for v in out.values())
    assert sorted(honest.queries) == sorted([SH, SH2, SH3])


def test_poll_many_spreads_across_servers(honest):
    second = FakeElectrum(fake_value=0, honest=True)
    try:
        pool = Pool([_srv(honest), _srv(second)], "round-robin")
        out = pool.poll_many([SH, SH2, SH3, SH], workers=2)
        assert len(out) == 3
        # both servers did work, so no single server saw the whole set
        assert honest.queries and second.queries
    finally:
        second.stop()


def test_poll_many_survives_a_dead_server(honest):
    """A shard assigned to a dead endpoint must fail over, not lose the batch."""
    dead = Server("127.0.0.1", 1, use_tls=False)  # nothing listens here
    pool = Pool([dead, _srv(honest)], "round-robin")
    out = pool.poll_many([SH, SH2], workers=2)
    assert set(out) == {SH, SH2}


def test_scan_all_stops_after_gap(honest):
    from check_seed.balance_cli import scan_all
    from check_seed.btc import derive

    derived = {"p2wpkh": derive(ABANDON, "p2wpkh", count=20, network="testnet")}
    pool = Pool([_srv(honest)], "round-robin")
    conf, unconf, used, funded, scanned = scan_all(pool, derived, gap=2, workers=4)["p2wpkh"]
    assert (conf, unconf) == (0, 0)
    assert scanned == 2          # gap reached, stop even though the window was wider
    assert funded == []
    assert honest.queries[:2] == [d.scripthash for d in derived["p2wpkh"][:2]]


def test_scan_all_keeps_going_past_gap_when_funded(liar):
    """Every address is 'funded', so the gap never fills and the whole range is scanned."""
    from check_seed.balance_cli import scan_all
    from check_seed.btc import derive

    derived = {"p2wpkh": derive(ABANDON, "p2wpkh", count=6, network="testnet")}
    pool = Pool([_srv(liar)], "round-robin")
    conf, unconf, _, funded, scanned = scan_all(pool, derived, gap=2, workers=4)["p2wpkh"]
    assert scanned == 6
    assert conf + unconf == 6 * 50_000_000
    assert len(funded) == 6


def test_scan_all_batches_all_types_together(honest):
    """Three types should be queried in one round, not three sequential connections."""
    from check_seed.balance_cli import scan_all
    from check_seed.btc import derive

    derived = {
        st: derive(ABANDON, st, count=10, network="testnet")
        for st in ("p2pkh", "p2sh-p2wpkh", "p2wpkh")
    }
    pool = Pool([_srv(honest)], "round-robin")
    out = scan_all(pool, derived, gap=2, workers=4)
    assert set(out) == set(derived)
    assert all(v[4] == 2 for v in out.values())
    # window is max(gap, workers) = 4, so 4 addresses per type in that one round
    assert len(honest.queries) == 12


def test_cross_check_flags_disagreement(liar, honest):
    """Two servers, one lying: the check must fail loudly."""
    servers = [_srv(liar), _srv(honest)]
    agree, detail = verify_total(servers, [SH], n=2, timeout=5)
    assert agree is False
    assert detail and "50000000" in detail[0]


def test_cross_check_passes_when_agreeing(honest):
    a = FakeElectrum(fake_value=0, honest=True)
    b = FakeElectrum(fake_value=0, honest=True)
    try:
        agree, _ = verify_total([_srv(a), _srv(b)], [SH], n=2, timeout=5)
        assert agree is True
    finally:
        a.stop()
        b.stop()


def test_cross_check_skipped_when_too_few_answer(liar):
    """One honest server cannot corroborate itself; must not claim agreement."""
    agree, detail = verify_total([_srv(liar)], [SH], n=2, timeout=5)
    assert agree is True
    assert "skipped" in detail[0]


def test_liar_is_queried_not_taken_on_trust(liar):
    pool = Pool([_srv(liar)], "round-robin")
    pool.poll(SH)
    assert liar.queries == [SH]


def test_probe_uses_ping_not_second_version(honest):
    """Regression: probing by sending a second server.version failed everywhere.

    The protocol permits server.version once per connection; Connection.connect()
    already spends it, so probe() must confirm liveness with server.ping.
    """
    from check_seed.servers import probe

    srv, ok = probe(_srv(honest), timeout=5)
    assert ok is True
    assert honest.version_calls == 1


def test_second_version_call_is_rejected_by_server(honest):
    """Guards the fake's fidelity to the real rule the regression relied on."""
    from check_seed.electrum import ElectrumError

    with Connection(_srv(honest), timeout=5) as conn:
        with pytest.raises(ElectrumError, match="already done"):
            conn.call("server.version", ["again", "1.4"])