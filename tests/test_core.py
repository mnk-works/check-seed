"""Tests use only public BIP39 test vectors. No real funds are involved."""

from mnemonic import Mnemonic

from check_seed import check_mnemonic, redact
from check_seed.core import fingerprint, read_entries

VALID = {
    12: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    15: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
    18: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
    21: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
    24: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
}


def test_all_valid_lengths_pass():
    for words, phrase in VALID.items():
        valid, count, reason, entropy = check_mnemonic(phrase)
        assert valid, f"{words} words rejected: {reason}"
        assert count == words
        assert entropy == words * 11 - words // 3


def test_whitespace_is_normalised():
    spaced = "  " + VALID[12].replace(" ", "   ") + "\n"
    assert check_mnemonic(spaced)[0] is True


def test_empty_phrase():
    assert check_mnemonic("")[0] is False


def test_bad_word_count():
    valid, count, reason, _ = check_mnemonic(" ".join(["abandon"] * 11))
    assert not valid and "word count" in reason


def test_unknown_word_reported():
    phrase = VALID[12].replace("about", "zzzzzz")
    valid, _, reason, _ = check_mnemonic(phrase)
    assert not valid and "wordlist" in reason and "zzzzzz" in reason


def test_reordered_words_fail_checksum():
    words = VALID[12].split()
    # swap two *distinct* words - the first 11 are all "abandon"
    words[0], words[-1] = words[-1], words[0]
    valid, _, reason, _ = check_mnemonic(" ".join(words))
    assert not valid and "checksum" in reason


def test_redact_hides_every_word():
    out = redact(VALID[12])
    assert "abandon" not in out and out.count("***") == 12


def test_fingerprint_is_stable_and_distinct():
    assert fingerprint(VALID[12]) == fingerprint(VALID[12])
    assert fingerprint(VALID[12]) != fingerprint(VALID[24])
    assert len(fingerprint(VALID[12])) == 16


def test_fingerprint_accounts_for_passphrase():
    assert fingerprint(VALID[12], "extra") != fingerprint(VALID[12])


def test_read_entries_skips_comments_and_blanks(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text("# comment\n\n  \n" + VALID[12] + "\n" + VALID[24] + "\n", encoding="utf-8")
    entries = read_entries(f)
    assert [n for n, _ in entries] == [4, 5]
    assert entries[0][1] == VALID[12]


def test_roundtrip_against_reference_mnemonic():
    """Our validator must agree with the reference impl on random entropy."""
    m = Mnemonic("english")
    for n_bytes in (16, 20, 24, 28, 32):
        phrase = m.to_mnemonic(bytes(range(n_bytes)))
        assert check_mnemonic(phrase)[0] is m.check(phrase)