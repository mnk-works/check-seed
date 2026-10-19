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
    total, key = pool.poll(SH)
    assert total == 0
    assert key == f"127.0.0.1:{honest.port}"


def test_pool_poll_reads_lie_from_single_server(liar):
    """A lone liar will happily report a big balance - which is the whole risk."""
    pool = Pool([_srv(liar)], "round-robin")
    total, _ = pool.poll(SH)
    assert total == 50_000_000


# --- the security property ------------------------------------------------

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