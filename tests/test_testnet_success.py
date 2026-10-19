"""Tests for testnet support and the success-file log."""

from __future__ import annotations

import pytest

from check_seed.balance_cli import append_success
from check_seed.btc import derive, scripthash_from_address

ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
OTHER = (
    "legal winner thank year wave sausage worth useful "
    "legal winner thank yellow"
)


# --- testnet derivation ---------------------------------------------------

def test_testnet_addresses_match_published_bip_vectors():
    """SLIP-0044 coin type 1 for testnet, so paths are 44'/1', 49'/1', 84'/1'."""
    assert derive(ABANDON, "p2wpkh", 1, network="testnet")[0].address == \
        "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"
    assert derive(ABANDON, "p2sh-p2wpkh", 1, network="testnet")[0].address == \
        "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"
    assert derive(ABANDON, "p2pkh", 1, network="testnet")[0].address == \
        "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV"


def test_testnet_differs_from_mainnet():
    """Different coin type means different keys, not just different encoding."""
    main = derive(ABANDON, "p2wpkh", 1, network="mainnet")[0]
    test = derive(ABANDON, "p2wpkh", 1, network="testnet")[0]
    assert main.address != test.address
    assert main.scripthash != test.scripthash


@pytest.mark.parametrize("script_type", ["p2pkh", "p2sh-p2wpkh", "p2wpkh"])
def test_testnet_address_path_agrees_with_derive(script_type):
    for d in derive(ABANDON, script_type, count=3, network="testnet"):
        assert scripthash_from_address(d.address, "testnet") == d.scripthash


def test_mainnet_address_rejected_on_testnet():
    addr = derive(ABANDON, "p2wpkh", 1, network="mainnet")[0].address
    with pytest.raises(ValueError, match="not valid testnet"):
        scripthash_from_address(addr, "testnet")


def test_testnet_address_rejected_on_mainnet():
    addr = derive(ABANDON, "p2wpkh", 1, network="testnet")[0].address
    with pytest.raises(ValueError, match="not valid mainnet"):
        scripthash_from_address(addr, "mainnet")


def test_testnet_p2pkh_version_byte():
    """Testnet P2PKH uses 0x6f, mainnet 0x00 - the guard must catch a mix-up."""
    addr = derive(ABANDON, "p2pkh", 1, network="testnet")[0].address
    assert addr[0] in ("m", "n")  # testnet P2PKH prefix
    with pytest.raises(ValueError):
        scripthash_from_address(addr, "mainnet")


def test_bad_network_name():
    with pytest.raises(ValueError, match="network"):
        derive(ABANDON, "p2wpkh", 1, network="regtest")


# --- success log ----------------------------------------------------------

def test_append_success_creates_file(tmp_path):
    path = tmp_path / "success.txt"
    append_success(str(path), "testnet", ABANDON, 12345, 3, ["s1:50002"])
    text = path.read_text()
    assert ABANDON in text
    assert "testnet" in text
    assert "0.00012345 BTC" in text
    assert "line 3" in text


def test_append_success_does_not_overwrite(tmp_path):
    path = tmp_path / "success.txt"
    append_success(str(path), "testnet", ABANDON, 1000, 3, [])
    append_success(str(path), "testnet", OTHER, 2000, 4, [])
    text = path.read_text()
    assert ABANDON in text and OTHER in text
    # both entries survive, in order
    assert text.index(ABANDON) < text.index(OTHER)
    assert text.count("# ") >= 2


def test_append_success_is_commentated(tmp_path):
    """Each entry is paired with a comment line so the file stays readable."""
    path = tmp_path / "success.txt"
    append_success(str(path), "mainnet", ABANDON, 1, 1, [])
    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    assert lines[0].startswith("# ")
    assert lines[1] == ABANDON


def test_append_success_permissions(tmp_path):
    import os
    import stat

    path = tmp_path / "success.txt"
    append_success(str(path), "testnet", ABANDON, 1, 1, [])
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_append_success_deduplicates(tmp_path):
    """Re-running against the same funded phrase must not pile up entries."""
    path = tmp_path / "success.txt"
    assert append_success(str(path), "testnet", ABANDON, 1000, 3, []) is True
    assert append_success(str(path), "testnet", ABANDON, 1000, 3, []) is False
    assert path.read_text().count(ABANDON) == 1
    # but a different phrase is still appended
    assert append_success(str(path), "testnet", OTHER, 2000, 4, []) is True
    assert path.read_text().count(OTHER) == 1


def test_phrase_already_logged_handles_missing_file(tmp_path):
    from check_seed.balance_cli import phrase_already_logged

    assert phrase_already_logged(str(tmp_path / "nope.txt"), ABANDON) is False