"""check-seed: validate BIP39 seed phrases without leaking them."""

from .core import CheckResult, check_mnemonic, load_seeds, redact

__all__ = ["CheckResult", "check_mnemonic", "load_seeds", "redact"]