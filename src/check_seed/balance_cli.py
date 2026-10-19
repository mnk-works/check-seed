"""check-balances: look up Bitcoin balances for local seeds via Electrum servers.

The seed is never transmitted. Addresses are derived locally; only the resulting
scripthashes (one-way hashes of public keys) are sent to the servers, exactly as
any Bitcoin wallet does.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from .btc import SCRIPT_TYPES, derive, fmt_btc, mask_address, scripthash_from_address
from .core import check_mnemonic, read_entries
from .electrum import ElectrumError, Server, _utxo_value, load_servers
from .pool import Pool

BANNER = """\
NOTICE: seeds stay on this machine. Servers see only scripthashes (SHA256 of a
        script, derived from public keys) -- but they still learn your IP and
        which addresses you query. Use a distinct server per run, or route over
        Tor, if that matters.
        Network: {network}.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check-balances",
        description="Look up Bitcoin balances for seed phrases via public Electrum servers.",
        epilog="Balance figures come from the servers. Cross-check with --verify before acting.",
    )
    p.add_argument("file", nargs="?", default=None,
                   help="file of phrases (default: seeds.txt, or testnet-seeds.txt with --testnet)")
    p.add_argument("-s", "--servers", default=None,
                   help="server list (default: servers.txt, or servers-testnet.txt with --testnet)")
    p.add_argument(
        "--testnet", action="store_true",
        help="use Bitcoin testnet: testnet derivation, testnet server list",
    )
    p.add_argument(
        "--success-file", default=None, metavar="PATH",
        help="append phrases that have a balance to this file (default: success.txt)",
    )
    p.add_argument(
        "--no-success-file", action="store_true",
        help="do not record funded phrases",
    )
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


def scan(pool: Pool, derived, gap: int) -> tuple[int, int, set[str], list, int]:
    """Poll addresses until `gap` consecutive unused ones are found.

    Returns (confirmed, unconfirmed, servers_used, funded, scanned_count).
    """
    confirmed = unconfirmed = 0
    used: set[str] = set()
    funded: list = []
    misses = 0
    scanned = 0
    for d in derived:
        scanned += 1
        try:
            c, u, key = pool.poll(d.scripthash)
        except ElectrumError as e:
            print(f"  ! {mask_address(d.address)}: {e}", file=sys.stderr)
            misses += 1
            if misses >= gap:
                break
            continue
        used.add(key)
        confirmed += c
        unconfirmed += u
        if c or u:
            funded.append((d, c + u))
            misses = 0
        else:
            misses += 1
        if misses >= gap:
            break
    return confirmed, unconfirmed, used, funded, scanned


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
            sh = scripthash_from_address(addr, args.network)
        except ValueError as e:
            print(f"{mask_address(addr)}: {e}", file=sys.stderr)
            problems += 1
            continue
        try:
            conf, unconf, key = pool.poll(sh)
        except ElectrumError as e:
            print(f"{mask_address(addr)}: {e}", file=sys.stderr)
            problems += 1
            continue

        label = "BALANCED" if (conf or unconf) else "empty"
        extra = f" (+{fmt_btc(unconf)} unconfirmed)" if unconf else ""
        print(f"{mask_address(addr)}: {label}  {fmt_btc(conf)}{extra}  [via {key}]")

        if args.verify and conf:
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


def phrase_already_logged(path: str, phrase: str) -> bool:
    """True if this exact phrase already appears in the success log."""
    p = Path(path)
    if not p.is_file():
        return False
    return phrase in p.read_text(encoding="utf-8").splitlines()


def append_success(path: str, network: str, phrase: str, total_sats: int,
                  lineno: int, servers: list[str]) -> bool:
    """Append a funded phrase to the success log. Never truncates.

    Returns False if the phrase is already present, so repeated runs do not pile
    up duplicate entries.

    The file holds real seed phrases, so it must stay out of version control -
    .gitignore covers success.txt for that reason.
    """
    if phrase_already_logged(path, phrase):
        return False

    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(
            f"# {stamp} {network} line {lineno} "
            f"{fmt_btc(total_sats)} [{', '.join(servers)}]\n"
            f"{phrase}\n"
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best effort; not all filesystems support it
    return True


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    network = "testnet" if args.testnet else "mainnet"
    args.network = network

    if not args.quiet_ok:
        print(BANNER.format(network=network), file=sys.stderr)

    if args.file is None:
        args.file = "testnet-seeds.txt" if args.testnet else "seeds.txt"
    if args.servers is None:
        args.servers = "servers-testnet.txt" if args.testnet else "servers.txt"
    if args.success_file is None:
        args.success_file = "success.txt"

    srv_path = Path(args.servers)

    if args.refresh_servers:
        from .servers import refresh, write_list

        print(f"fetching canonical {network} Electrum directory and probing endpoints...")
        try:
            live = refresh(network=network)
        except (OSError, ValueError) as e:
            print(f"error: could not fetch server list: {e}", file=sys.stderr)
            return 2
        write_list(str(srv_path), live, network=network)
        print(f"wrote {len(live)} live {network} servers to {srv_path}")
        return 0

    if not srv_path.is_file():
        print(
            f"error: no {network} server list at {srv_path}\n"
            f"       create one with: check-balances --refresh-servers"
            + (" --testnet" if args.testnet else ""),
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

    funded_count = 0
    added_count = 0
    disagreements = 0

    for lineno, phrase in entries:
        valid, _, reason, _ = check_mnemonic(phrase)
        label = f"line {lineno}"
        if not valid:
            print(f"{label}: skipping, not a valid BIP39 phrase ({reason})")
            continue

        total_all = 0
        total_unconf = 0
        used_all: set[str] = set()
        rows: list[str] = []
        sh_list: list[str] = []

        for st in types:
            derived = derive(phrase, st, count=args.count, network=network)
            conf, unconf, used, funded, scanned = scan(pool, derived, args.gap)
            total_all += conf
            total_unconf += unconf
            used_all |= used
            sh_list.extend(d.scripthash for d in derived)
            note = f", {fmt_btc(unconf)} unconfirmed" if unconf else ""
            rows.append(
                f"      {st:<12} {fmt_btc(conf):>18}{note:<32} "
                f"({len(funded)} funded of {scanned} scanned)"
            )

        header = "BALANCED" if (total_all or total_unconf) else "empty"
        extra = f" (+{fmt_btc(total_unconf)} unconfirmed)" if total_unconf else ""
        print(f"{label}: {header}  {fmt_btc(total_all)}{extra}  "
              f"[{', '.join(sorted(used_all)) or 'no server'}]")
        for r in rows:
            print(r)

        if args.verify and (total_all or total_unconf):
            agree, detail = verify_total(pool.servers, sh_list, args.verify, args.timeout)
            flag = "agree" if agree else "DISAGREE"
            print(f"      cross-check {args.verify} servers: {flag} (includes unconfirmed)")
            for d in detail:
                print(f"        {d}")
            if not agree:
                disagreements += 1
        elif args.verify:
            print("      cross-check: skipped, balance is zero")

        if total_all or total_unconf:
            funded_count += 1
            if not args.no_success_file:
                added = append_success(
                    args.success_file, network, phrase, total_all + total_unconf,
                    lineno, sorted(used_all),
                )
                if added:
                    added_count += 1
                    print(f"      appended to {args.success_file}")
                else:
                    print(f"      already in {args.success_file}, not duplicated")

    if funded_count and not args.no_success_file:
        skipped = funded_count - added_count
        msg = f"\n{funded_count} funded phrase(s)"
        msg += f", {added_count} newly appended to {args.success_file}"
        if skipped:
            msg += f" ({skipped} already present)"
        print(msg)

    if args.stats:
        print("\nserver pool:\n" + pool.stats())

    if disagreements:
        print(f"\nWARNING: {disagreements} seed(s) had servers disagree on the balance")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())