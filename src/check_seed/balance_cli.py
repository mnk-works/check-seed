"""check-balances: look up Bitcoin balances for local seeds via Electrum servers.

The seed is never transmitted. Addresses are derived locally; only the resulting
scripthashes (one-way hashes of public keys) are sent to the servers, exactly as
any Bitcoin wallet does.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .btc import SCRIPT_TYPES, derive, fmt_btc, mask_address, scripthash_from_address
from .core import check_mnemonic, read_entries
from .electrum import ElectrumError, Server, _utxo_value, load_servers
from .pool import Pool

BANNER = (
    "NOTICE: seeds stay on this machine. Servers see only scripthashes (hashes of\n"
    "        public keys) -- but they still learn your IP and which addresses you\n"
    "        query. Use a distinct server per run, or route over Tor, if that matters.\n"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check-balances",
        description="Look up Bitcoin balances for seed phrases via public Electrum servers.",
        epilog="Balance figures come from the servers. Cross-check with --verify before acting.",
    )
    p.add_argument("file", nargs="?", default="seeds.txt", help="file of phrases (default: seeds.txt)")
    p.add_argument("-s", "--servers", default="servers.txt", help="server list (default: servers.txt)")
    p.add_argument(
        "-t", "--script-type", default="all",
        help=f"one of {', '.join(SCRIPT_TYPES)} or 'all' (default: all)",
    )
    p.add_argument("-n", "--count", type=int, default=20, help="max addresses per type (default: 20)")
    p.add_argument("-g", "--gap", type=int, default=6, help="stop after N consecutive unused (default: 6)")
    p.add_argument(
        "--strategy", default="round-robin",
        choices=("round-robin", "fastest", "random", "failover"),
        help="how to spread requests across servers (default: round-robin)",
    )
    p.add_argument("--probe", action="store_true", help="only test which servers are reachable")
    p.add_argument(
        "--refresh-servers", action="store_true",
        help="regenerate the server list from the canonical Electrum directory",
    )
    p.add_argument(
        "-a", "--address", action="append", default=[], metavar="ADDR",
        help="check a specific address directly (repeatable); skips seed derivation",
    )
    p.add_argument("--stats", action="store_true", help="print per-server health after the run")
    p.add_argument(
        "--verify", type=int, default=0, metavar="N",
        help="recompute each total from N independent servers and flag disagreement",
    )
    p.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds")
    p.add_argument("--quiet-ok", action="store_true", help="suppress the notice banner")
    return p


def scan(pool: Pool, derived, gap: int) -> tuple[int, set[str], list, int]:
    """Poll addresses until `gap` consecutive unused ones are found.

    Returns (total_sats, servers_used, funded_addresses, scanned_count).
    """
    total = 0
    used: set[str] = set()
    funded: list = []
    misses = 0
    scanned = 0
    for d in derived:
        scanned += 1
        try:
            sats, key = pool.poll(d.scripthash)
        except ElectrumError as e:
            print(f"  ! {mask_address(d.address)}: {e}", file=sys.stderr)
            misses += 1
            if misses >= gap:
                break
            continue
        used.add(key)
        if sats:
            total += sats
            funded.append((d, sats))
            misses = 0
        else:
            misses += 1
        if misses >= gap:
            break
    return total, used, funded, scanned


def verify_total(servers: list[Server], scripthashes: list[str], n: int, timeout: float) -> tuple[bool, list[str]]:
    """Recompute a total from up to n distinct servers and compare."""
    from .electrum import Connection

    results: dict[str, int] = {}
    for srv in servers[:n]:
        try:
            with Connection(srv, timeout=timeout) as conn:
                results[srv.key] = sum(
                    sum(_utxo_value(u) for u in conn.listunspent(sh))
                    for sh in scripthashes
                )
        except (ElectrumError, OSError):
            continue
    if len(results) < 2:
        return True, ["verify skipped: fewer than 2 servers answered"]
    distinct = set(results.values())
    agree = len(distinct) == 1
    detail = ", ".join(f"{k}={fmt_btc(v)}" for k, v in results.items())
    return agree, [detail]


def check_addresses(pool: Pool, args) -> int:
    """Query explicit addresses, bypassing seed derivation entirely."""
    problems = 0
    for addr in args.address:
        try:
            sh = scripthash_from_address(addr)
        except ValueError as e:
            print(f"{mask_address(addr)}: {e}", file=sys.stderr)
            problems += 1
            continue
        try:
            total, key = pool.poll(sh)
        except ElectrumError as e:
            print(f"{mask_address(addr)}: {e}", file=sys.stderr)
            problems += 1
            continue

        label = "BALANCED" if total else "empty"
        print(f"{mask_address(addr)}: {label}  {fmt_btc(total)}  [via {key}]")

        if args.verify:
            agree, detail = verify_total(pool.servers, [sh], args.verify, args.timeout)
            print(f"      cross-check {args.verify} servers: {'agree' if agree else 'DISAGREE'}")
            for d in detail:
                print(f"        {d}")
            if not agree:
                problems += 1

    if args.stats:
        print("\nserver pool:\n" + pool.stats())
    if problems:
        print(f"\nWARNING: {problems} problem(s) found")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.quiet_ok:
        print(BANNER, file=sys.stderr)

    srv_path = Path(args.servers)

    if args.refresh_servers:
        from .servers import refresh, write_list

        print("fetching canonical Electrum directory and probing endpoints...")
        try:
            live = refresh()
        except OSError as e:
            print(f"error: could not fetch server list: {e}", file=sys.stderr)
            return 2
        write_list(str(srv_path), live)
        print(f"wrote {len(live)} live servers to {srv_path}")
        return 0

    if not srv_path.is_file():
        print(
            f"error: no server list at {srv_path}\n"
            f"       create one with: check-balances --refresh-servers",
            file=sys.stderr,
        )
        return 2

    pool = Pool(load_servers(str(srv_path)), strategy=args.strategy)

    if args.probe:
        print(f"probing {len(pool)} servers...\n")
        rows = pool.probe_all()
        up = [r for r in rows if r[1]]
        for srv, ok, detail in sorted(rows, key=lambda r: (not r[1], r[0].key)):
            print(f"  {'OK ' if ok else 'FAIL'}  {srv.key:<44} {detail}")
        print(f"\n{len(up)}/{len(rows)} reachable")
        return 0 if up else 1

    if args.address:
        return check_addresses(pool, args)

    seed_path = Path(args.file)
    if not seed_path.is_file():
        print(f"error: no seed file at {seed_path}", file=sys.stderr)
        return 2

    entries = read_entries(seed_path)
    if not entries:
        print(f"no phrases found in {seed_path}")
        return 0

    types = list(SCRIPT_TYPES) if args.script_type == "all" else [args.script_type]
    if any(t not in SCRIPT_TYPES for t in types):
        print(f"error: --script-type must be one of {SCRIPT_TYPES} or 'all'", file=sys.stderr)
        return 2

    all_funded = False
    disagreements = 0

    for lineno, phrase in entries:
        valid, _, reason, _ = check_mnemonic(phrase)
        label = f"line {lineno}"
        if not valid:
            print(f"{label}: skipping, not a valid BIP39 phrase ({reason})")
            continue

        total_all = 0
        used_all: set[str] = set()
        rows: list[str] = []
        sh_list: list[str] = []

        for st in types:
            derived = derive(phrase, st, count=args.count)
            sub, used, funded, scanned = scan(pool, derived, args.gap)
            total_all += sub
            used_all |= used
            sh_list.extend(d.scripthash for d in derived)
            rows.append(
                f"      {st:<12} {fmt_btc(sub):>18}   "
                f"({len(funded)} funded of {scanned} scanned)"
            )

        header = "BALANCED" if total_all else "empty"
        print(f"{label}: {header}  {fmt_btc(total_all)}  [{', '.join(sorted(used_all)) or 'no server'}]")
        for r in rows:
            print(r)

        if args.verify and total_all:
            agree, detail = verify_total(pool.servers, sh_list, args.verify, args.timeout)
            flag = "agree" if agree else "DISAGREE"
            print(f"      cross-check {args.verify} servers: {flag}")
            for d in detail:
                print(f"        {d}")
            if not agree:
                disagreements += 1
        elif args.verify:
            print("      cross-check: skipped, balance is zero")

        all_funded |= total_all > 0

    if args.stats:
        print("\nserver pool:\n" + pool.stats())

    if disagreements:
        print(f"\nWARNING: {disagreements} seed(s) had servers disagree on the balance")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())