"""Command line entry point for check-seed."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import check_mnemonic, fingerprint, read_entries

BANNER = (
    "WARNING: seed phrases are private keys. Run offline on a trusted machine.\n"
    "         Output is redacted by default; --show-seeds prints phrases in full.\n"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check-seed",
        description="Validate BIP39 seed phrases from a file, one per line.",
        epilog=(
            "This command is offline only: it validates the checksum and wordlist, "
            "and never touches the network.\n"
            "To look up balances (mainnet or --testnet), use: check-balances"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "file",
        nargs="?",
        default="seeds.txt",
        help="file of phrases, one per line (default: seeds.txt)",
    )
    p.add_argument(
        "-q", "--quiet", action="store_true", help="print only a summary line"
    )
    p.add_argument(
        "--reveal",
        action="store_true",
        help="print the full phrase for VALID phrases only (dangerous)",
    )
    p.add_argument(
        "--preview",
        action="store_true",
        help="show first/last two words of each phrase instead of masking",
    )
    p.add_argument(
        "--fingerprint",
        action="store_true",
        help="show a stable non-reversible id per phrase (safe to share)",
    )
    p.add_argument(
        "--quiet-ok", action="store_true", help="suppress the warning banner"
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    if not args.quiet_ok:
        print(BANNER, file=sys.stderr)

    try:
        entries = read_entries(path)
    except UnicodeDecodeError:
        print(f"error: {path} is not UTF-8 text", file=sys.stderr)
        return 2

    if not entries:
        print(f"no phrases found in {path}")
        return 0

    valid_count = 0
    for lineno, phrase in entries:
        valid, count, reason, entropy = check_mnemonic(phrase)
        valid_count += valid

        if args.quiet:
            continue

        mark = "PASS" if valid else "FAIL"
        detail = f"[{count:>2} words, {entropy} bits]" if valid else f"[{count:>2} words]"
        line = f"{lineno:>4}  {mark}  {detail}  {reason}"

        if args.fingerprint:
            line += f"  id={fingerprint(phrase)}"
        elif args.preview:
            line += f"  {' '.join(phrase.split()[:2])} ... " + " ".join(phrase.split()[-2:])
        elif args.reveal and valid:
            line += f"\n      {phrase}"

        print(line)

    total = len(entries)
    print(f"\n{valid_count}/{total} valid ({total - valid_count} invalid)")
    return 0 if valid_count == total else 1


if __name__ == "__main__":
    raise SystemExit(main())