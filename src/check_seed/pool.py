"""Server pool with round-robin / fastest / random selection and health tracking.

Spreading queries across several servers is also a privacy win: no single
operator sees your full address set.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

from .electrum import Connection, ElectrumError, Server, _utxo_parts

T = TypeVar("T")

STRATEGIES = ("round-robin", "fastest", "random", "failover")


class Pool:
    def __init__(self, servers: list[Server], strategy: str = "round-robin") -> None:
        if not servers:
            raise ValueError("no servers configured")
        if strategy not in STRATEGIES:
            raise ValueError(f"unknown strategy: {strategy} (expected one of {STRATEGIES})")
        self.servers = servers
        self.strategy = strategy
        self._i = 0

    def __len__(self) -> int:
        return len(self.servers)

    def _live(self) -> list[Server]:
        live = [s for s in self.servers if s.healthy]
        return live or list(self.servers)

    def _ordered(self, offset: int = 0) -> list[Server]:
        live = self._live()
        if self.strategy == "fastest":
            timed = [s for s in live if s.latency_ms is not None]
            untimed = [s for s in live if s.latency_ms is None]
            return sorted(timed, key=lambda s: s.latency_ms) + untimed
        if self.strategy == "random":
            out = list(live)
            random.shuffle(out)
            return out
        if self.strategy == "failover":
            return list(live)
        start = (self._i + offset) % len(live)
        return live[start:] + live[:start]

    def __iter__(self) -> Iterator[Server]:
        return iter(self._ordered())

    def pick(self) -> Server:
        """Next server in rotation (round-robin) or best available."""
        srv = self._ordered()[0]
        if self.strategy == "round-robin":
            self._i = (self._i + 1) % len(self.servers)
        return srv

    def with_connection(self, fn: Callable[[Connection], T], retries: int = 2) -> tuple[T, Server]:
        """Run fn(conn) against a server, failing over on error.

        Round-robin advances on every attempt, so consecutive calls land on
        different servers and a failure immediately tries the next one.
        """
        last: Exception | None = None
        for attempt in range(retries + 1):
            candidates = self._ordered(attempt)
            srv = candidates[0]
            if self.strategy == "round-robin":
                self._i = (self._i + 1) % len(self.servers)
            try:
                t0 = time.monotonic()
                with Connection(srv) as conn:
                    result = fn(conn)
                srv.record_ok((time.monotonic() - t0) * 1000)
                return result, srv
            except (ElectrumError, OSError) as e:
                srv.record_fail()
                last = e
                continue
        raise ElectrumError(f"all servers failed ({retries + 1} attempts): {last}")

    def poll(self, scripthash: str) -> tuple[int, int, str]:
        """Sum unspent outputs for one scripthash.

        Returns (confirmed_sats, unconfirmed_sats, server_key). height <= 0 marks
        a mempool output.
        """
        def work(conn: Connection) -> tuple[int, int]:
            confirmed = unconfirmed = 0
            for u in conn.listunspent(scripthash):
                value, height = _utxo_parts(u)
                if height > 0:
                    confirmed += value
                else:
                    unconfirmed += value
            return confirmed, unconfirmed

        (confirmed, unconfirmed), srv = self.with_connection(work)
        return confirmed, unconfirmed, srv.key

    def poll_many(self, scripthashes: list[str], workers: int = 8) -> dict[str, tuple[int, int, str]]:
        """Query many scripthashes concurrently, reusing one connection per worker.

        Addresses are sharded across worker threads; each worker holds a single
        keep-alive connection to one server for its whole shard. This removes the
        per-address TCP+TLS handshake, which dominates latency.

        Returns {scripthash: (confirmed, unconfirmed, server_key)}. A shard whose
        server fails is retried on another server; anything still unsolved is
        simply absent from the result, so the caller can retry those individually
        instead of losing the whole batch.
        """
        if not scripthashes:
            return {}

        servers = self._ordered()
        if not servers:
            raise ElectrumError("no servers available")

        n = self._n_workers(len(servers), len(scripthashes), workers)
        shards: list[list[str]] = [[] for _ in range(n)]
        for i, sh in enumerate(scripthashes):
            shards[i % n].append(sh)

        results: dict[str, tuple[int, int, str]] = {}
        lock = threading.Lock()

        def solve(conn: Connection, shard: list[str], key: str) -> dict[str, tuple[int, int, str]]:
            out: dict[str, tuple[int, int, str]] = {}
            for sh, utxos in zip(shard, conn.listunspent_many(shard), strict=True):
                confirmed = unconfirmed = 0
                for u in utxos:
                    value, height = _utxo_parts(u)
                    if height > 0:
                        confirmed += value
                    else:
                        unconfirmed += value
                out[sh] = (confirmed, unconfirmed, key)
            return out

        def run_shard(shard: list[str], start: int) -> None:
            # Walk the server ring until one accepts the whole shard.
            for attempt in range(len(servers)):
                srv = servers[(start + attempt) % len(servers)]
                t0 = time.monotonic()
                conn = Connection(srv)
                try:
                    conn.connect()
                    local = solve(conn, shard, srv.key)
                    with lock:
                        results.update(local)
                    srv.record_ok((time.monotonic() - t0) * 1000)
                    return
                except (ElectrumError, OSError):
                    srv.record_fail()
                finally:
                    conn.close()
            # Every server refused this shard; leave it out and let the caller retry.

        with ThreadPoolExecutor(max_workers=n) as ex:
            futures = [ex.submit(run_shard, shard, i) for i, shard in enumerate(shards)]
            for fut in futures:
                fut.result()

        if self.strategy == "round-robin":
            self._i = (self._i + n) % len(self.servers)
        return results

    @staticmethod
    def _n_workers(n_servers: int, n_queries: int, requested: int) -> int:
        """Never more workers than servers (one connection each) or queries."""
        return max(1, min(requested, n_servers, n_queries))

    def probe_all(self, timeout: float = 5.0) -> list[tuple[Server, bool, str]]:
        """Check which servers are reachable. Returns (server, ok, detail)."""
        def one(srv: Server) -> tuple[Server, bool, str]:
            t0 = time.monotonic()
            try:
                with Connection(srv, timeout=timeout) as conn:
                    conn.ping()
                ms = (time.monotonic() - t0) * 1000
                srv.record_ok(ms)
                return srv, True, f"{ms:.0f}ms"
            except (ElectrumError, OSError) as e:
                srv.record_fail()
                return srv, False, str(e)[:60]

        with ThreadPoolExecutor(max_workers=min(len(self.servers), 24)) as ex:
            return list(ex.map(one, self.servers))

    def stats(self) -> str:
        rows = []
        for s in self.servers:
            mark = "up  " if s.healthy else "DOWN"
            lat = f"{s.latency_ms:6.0f}ms" if s.latency_ms is not None else "     - "
            rows.append(f"  {mark} {s.key:<44} {lat}  ok={s.successes} fail={s.failures}")
        return "\n".join(rows)