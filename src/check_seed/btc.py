"""Local address derivation from a seed phrase, and Electrum scripthash computation.

Everything in this module runs on your machine. Key material never leaves it.
"""

from __future__ import annotations

from dataclasses import dataclass

from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
)

# Electrum scripthash = HASH160 of the "script pubkey" preimage it indexes.
#   P2PKH / P2WPKH : HASH160(pubkey)
#   P2SH-P2WPKH    : HASH160(0x0014 || HASH160(pubkey))   (the redeem script)
SCRIPT_TYPES = ("p2pkh", "p2sh-p2wpkh", "p2wpkh")
DERIVATION = {"p2pkh": "bip44", "p2sh-p2wpkh": "bip49", "p2wpkh": "bip84"}


# --- output script construction -------------------------------------------
# Electrum's scripthash is SHA256 of the raw output script, rendered in
# reversed byte order - NOT hash160. See electrum/bitcoin.py:script_to_scripthash.


def _hash160(data: bytes) -> bytes:
    import hashlib

    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def script_to_scripthash(script: bytes) -> str:
    """Electrum scripthash: SHA256(output script), reversed, hex."""
    import hashlib

    return hashlib.sha256(script).digest()[::-1].hex()


def p2pkh_script(h160: bytes) -> bytes:
    """OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG"""
    return bytes.fromhex("76a914") + h160 + bytes.fromhex("88ac")


def p2sh_script(h160: bytes) -> bytes:
    """OP_HASH160 <20> OP_EQUAL"""
    return bytes.fromhex("a914") + h160 + bytes.fromhex("87")


def p2wpkh_script(h160: bytes) -> bytes:
    """OP_0 <20>"""
    return bytes.fromhex("0014") + h160


def p2wsh_script(h160: bytes) -> bytes:
    """OP_0 <32>"""
    return bytes.fromhex("0020") + h160


def scripthash_from_address(addr: str) -> str:
    """Electrum scripthash for an address.

    Rebuilds the output script the address pays to, then SHA256s it. Supports
    P2PKH, P2SH, P2WPKH and P2WSH. Taproot (P2TR) is not indexed by Electrum
    servers.
    """
    from bech32 import bech32_decode, convertbits
    from base58 import b58decode_check

    low = addr.lower()

    if low.startswith("bc1p"):
        raise ValueError(
            "taproot (P2TR) addresses are not indexed by Electrum servers"
        )

    if low.startswith("bc1"):
        # bech32 lib returns (None, None) on failure, else (hrp, data)
        hrp, data = bech32_decode(addr)
        if hrp != "bc" or not data:
            raise ValueError(f"unrecognised bech32 address: {addr}")
        witver = data[0]
        prog = convertbits(data[1:], 5, 8, False)
        if prog is None:
            raise ValueError(f"bad bech32 payload: {addr}")
        prog_b = bytes(prog)

        if witver == 0 and len(prog_b) == 20:
            return script_to_scripthash(p2wpkh_script(prog_b))
        if witver == 0 and len(prog_b) == 32:
            return script_to_scripthash(p2wsh_script(prog_b))
        if witver == 1:
            raise ValueError(
                "taproot (P2TR) addresses are not indexed by Electrum servers"
            )
        raise ValueError(f"unsupported witness program v{witver} len={len(prog_b)}")

    raw = b58decode_check(addr)
    if len(raw) != 21:
        raise ValueError(f"bad address payload: {addr}")
    version, payload = raw[0], raw[1:]
    if version == 0x00:      # mainnet P2PKH
        return script_to_scripthash(p2pkh_script(payload))
    if version in (0x05, 0xC4):  # mainnet / testnet P2SH
        return script_to_scripthash(p2sh_script(payload))
    raise ValueError(f"unsupported address version byte 0x{version:02x}")


@dataclass(frozen=True)
class Derived:
    """A derived address plus the preimage Electrum indexes it by."""

    index: int
    address: str
    scripthash: str
    script_type: str


def derive(seed_phrase: str, script_type: str = "p2wpkh", count: int = 20,
           passphrase: str = "") -> list[Derived]:
    """Derive `count` receive addresses from a seed, entirely locally.

    BIP44 (p2pkh), BIP49 (p2sh-p2wpkh) and BIP84 (p2wpkh) are supported, all on
    Bitcoin mainnet.
    """
    if script_type not in SCRIPT_TYPES:
        raise ValueError(f"script_type must be one of {SCRIPT_TYPES}")

    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate(passphrase)

    if script_type == "p2pkh":
        acct = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN).Purpose().Coin().Account(0)
    elif script_type == "p2sh-p2wpkh":
        acct = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN).Purpose().Coin().Account(0)
    else:
        acct = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN).Purpose().Coin().Account(0)

    change = acct.Change(Bip44Changes.CHAIN_EXT)

    out: list[Derived] = []
    for i in range(count):
        pubkey = change.AddressIndex(i).PublicKey()
        address = pubkey.ToAddress()
        pub_h160 = _hash160(pubkey.RawCompressed().ToBytes())

        if script_type == "p2pkh":
            script = p2pkh_script(pub_h160)
        elif script_type == "p2sh-p2wpkh":
            # redeem script is OP_0 <hash160(pubkey)>; P2SH wraps its hash160
            script = p2sh_script(_hash160(p2wpkh_script(pub_h160)))
        else:
            script = p2wpkh_script(pub_h160)

        out.append(
            Derived(
                index=i,
                address=address,
                scripthash=script_to_scripthash(script),
                script_type=script_type,
            )
        )
    return out


def mask_address(addr: str) -> str:
    """bc1qxy2k...7c3f - safe to show in logs and screenshots."""
    if len(addr) <= 12:
        return addr
    return f"{addr[:8]}...{addr[-6:]}"


def fmt_btc(sats: int) -> str:
    return f"{sats / 1e8:.8f} BTC"