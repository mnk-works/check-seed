"""Core validation logic for BIP39 seed phrases.

A BIP39 mnemonic is valid when it:
  1. contains only words from the official 2048-word English list,
  2. has a supported word count (12, 15, 18, 21 or 24),
  3. passes the SHA256 checksum of the entropy bits.

Validation is entirely offline and deterministic. It does NOT derive keys,
touch the network, or reveal whether a phrase holds funds.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from mnemonic import Mnemonic

VALID_WORD_COUNTS = (12, 15, 18, 21, 24)
_MNEMONIC = Mnemonic("english")
_WORD_INDEX: dict[str, int] = {w: i for i, w in enumerate(_MNEMONIC.wordlist)}


@dataclass(frozen=True)
class CheckResult:
    """Outcome of validating a single candidate phrase."""

    index: int
    raw: str
    valid: bool
    word_count: int
    reason: str
    entropy_bits: int | None = None

    @property
    def redacted(self) -> str:
        return redact(self.raw)

    @property
    def preview(self) -> str:
        """First and last two words only, middle elided."""
        words = self.raw.split()
        if len(words) <= 4:
            return self.redacted
        return " ".join([words[0], words[1], "...", words[-2], words[-1]])


def redact(phrase: str) -> str:
    """Mask every word so a phrase never lands in logs or terminal scrollback."""
    words = phrase.split()
    if not words:
        return ""
    return " ".join(f"{w[0]}***" for w in words)


def check_mnemonic(phrase: str) -> tuple[bool, int, str, int | None]:
    """Validate one phrase. Returns (valid, word_count, reason, entropy_bits)."""
    words = phrase.split()
    count = len(words)

    if count == 0:
        return False, 0, "empty phrase", None

    unknown = [w for w in words if w not in _WORD_INDEX]
    if unknown:
        shown = ", ".join(unknown[:3])
        extra = f" (+{len(unknown) - 3} more)" if len(unknown) > 3 else ""
        return False, count, f"not in BIP39 wordlist: {shown}{extra}", None

    if count not in VALID_WORD_COUNTS:
        return False, count, f"invalid word count (expected {'/'.join(map(str, VALID_WORD_COUNTS))})", None

    # check() requires single-space-separated words; normalise before hashing.
    normalised = " ".join(words)
    if not _MNEMONIC.check(normalised):
        return False, count, "checksum failed (typo, wrong word order, or wrong words)", None

    return True, count, "valid", count * 11 - count // 3


def load_seeds(path: str | Path) -> list[str]:
    """Read phrases from a text file, one per line.

    Blank lines and lines starting with '#' are ignored so the file can carry
    comments. Line numbers are not preserved here; use read_entries for that.
    """
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def read_entries(path: str | Path) -> list[tuple[int, str]]:
    """Like load_seeds but keeps the original 1-based line number."""
    out: list[tuple[int, str]] = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if stripped and not stripped.lstrip().startswith("#"):
            out.append((n, stripped))
    return out


def fingerprint(phrase: str, passphrase: str = "") -> str:
    """Non-reversible identifier for a phrase, for logs and dedup tables.

    Uses the BIP39 seed derivation so the same phrase+passphrase always maps to
    the same tag, while the value cannot be brute-forced back to the phrase
    without knowing it. Safe to share; it leaks nothing on its own.
    """
    seed = _MNEMONIC.to_seed(phrase, passphrase)
    return hashlib.sha256(b"check-seed/fingerprint/v1" + seed).hexdigest()[:16]