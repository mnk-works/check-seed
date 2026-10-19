"""Minimal Electrum server protocol client (JSON-RPC over TCP or TLS).

Only the read-only methods this tool needs are implemented. There is deliberately
no method here that uploads key material, and nothing that signs - the seed is
never passed to this module.

Note on TLS: Electrum servers commonly present self-signed certificates, so TLS
here gives you *encryption* but not *identity*. Without certificate pinning a
hostile server can still MITM you. See README.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
from dataclasses import dataclass, field

PROTOCOL = "1.4"
CLIENT = "check-seed 0.1"


class ElectrumError(Exception):
    pass


def _utxo_parts(u: object) -> tuple[int, int]:
    """Return (value_sats, height) from a listunspent entry.

    Modern ElectrumX / Fulcrum / electrs return objects
    ``{"tx_hash", "tx_pos", "height", "value"}``; older servers returned the
    positional array ``[height, tx_pos, value]``. Both appear in the wild.

    height <= 0 means unconfirmed (mempool). Strict on purpose: a malformed entry
    raises rather than defaulting to 0, because a silent 0 would understate a
    balance.
    """
    if isinstance(u, dict):
        if "value" not in u:
            raise ElectrumError(f"listunspent entry has no 'value' field: {u!r}")
        return int(u["value"]), int(u.get("height", 0))
    if isinstance(u, (list, tuple)) and len(u) >= 3:
        return int(u[2]), int(u[0])
    raise ElectrumError(f"unrecognised listunspent entry: {u!r}")


def _utxo_value(u: object) -> int:
    """Value only, regardless of confirmation state."""
    return _utxo_parts(u)[0]


@dataclass
class Server:
    host: str
    port: int
    use_tls: bool = False

    # health bookkeeping, managed by the pool
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    latency_ms: float | None = None
    down_until: float = 0.0
    history: list[float] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def healthy(self) -> bool:
        return time.monotonic() >= self.down_until

    def record_ok(self, ms: float) -> None:
        self.successes += 1
        self.consecutive_failures = 0
        self.latency_ms = ms
        self.history.append(ms)
        del self.history[:-20]

    def record_fail(self) -> None:
        self.failures += 1
        self.consecutive_failures += 1
        # exponential-ish cooldown, capped at 5 minutes
        self.down_until = time.monotonic() + min(5.0 * self.consecutive_failures, 300.0)


class Connection:
    """One short-lived connection to one Electrum server."""

    def __init__(self, server: Server, timeout: float = 8.0) -> None:
        self.server = server
        self.timeout = timeout
        self._next_id = 0
        self._sock: socket.socket | None = None
        self._fh = None

    def __enter__(self) -> "Connection":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        t0 = time.monotonic()
        try:
            raw = socket.create_connection((self.server.host, self.server.port), self.timeout)
            if self.server.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=self.server.host)
            raw.settimeout(self.timeout)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock = raw
            self._fh = raw.makefile("rwb")
        except OSError as e:
            raise ElectrumError(f"connect failed: {e}") from e

        try:
            self.call("server.version", [CLIENT, PROTOCOL])
        except ElectrumError:
            self.close()
            raise
        self.server.latency_ms = (time.monotonic() - t0) * 1000

    def close(self) -> None:
        try:
            if self._fh:
                self._fh.close()
        except OSError:
            pass
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        self._fh = self._sock = None

    def call(self, method: str, params: list | None = None) -> object:
        if self._fh is None:
            raise ElectrumError("not connected")
        self._next_id += 1
        msg = {"id": self._next_id, "method": method, "params": params or []}
        try:
            self._fh.write((json.dumps(msg) + "\n").encode())
            self._fh.flush()
        except OSError as e:
            raise ElectrumError(f"write failed: {e}") from e

        while True:
            line = self._fh.readline()
            if not line:
                raise ElectrumError("connection closed by server")
            line = line.strip()
            if not line:
                continue
            try:
                resp = json.loads(line.decode())
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise ElectrumError(f"bad response: {e}") from e

            # subscriptions / notices arrive unsolicited; skip them
            if isinstance(resp, dict) and resp.get("id") != self._next_id:
                continue
            if isinstance(resp, dict) and "error" in resp:
                raise ElectrumError(f"{method}: {resp['error']}")
            if isinstance(resp, dict) and "result" in resp:
                return resp["result"]
            raise ElectrumError(f"unexpected response to {method}")

    # --- read-only helpers -------------------------------------------------

    def listunspent(self, scripthash: str) -> list:
        """Unspent outputs as [height, tx_pos, value_sats]."""
        return self.call("blockchain.scripthash.listunspent", [scripthash]) or []

    def get_history(self, scripthash: str) -> list:
        """Txids touching the script as [[txid, height], ...]."""
        return self.call("blockchain.scripthash.get_history", [scripthash]) or []

    def get_balance(self, scripthash: str) -> dict:
        """Server-computed {confirmed, unconfirmed} in sats.

        Convenient, but it is the *server's* arithmetic. Prefer listunspent +
        local summation, or cross-check with a second server.
        """
        return self.call("blockchain.scripthash.get_balance", [scripthash]) or {}

    def ping(self) -> None:
        self.call("server.ping")


def parse_server(line: str, default_tls: bool | None = None) -> Server | None:
    """Parse `host`, `host:port`, `host:port:ssl` or `host:port:tcp`.

    With no explicit suffix, port 50001 is treated as plaintext (Electrum's
    convention) and anything else as TLS.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    tls = default_tls
    if line.lower().endswith(":ssl"):
        line, tls = line[:-4], True
    elif line.lower().endswith(":tcp"):
        line, tls = line[:-4], False

    if line.count(":") == 1:
        host, _, port_s = line.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            host, port = line, 50002
    elif line.count(":") > 1:  # bare IPv6, no port
        host, port = line.strip("[]"), 50002
    else:
        host, port = line, 50002

    if not host:
        return None
    if tls is None:
        tls = port != 50001
    return Server(host=host, port=port, use_tls=tls)


def load_servers(path: str, default_tls: bool | None = None) -> list[Server]:
    from pathlib import Path

    out: list[Server] = []
    seen: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        srv = parse_server(line, default_tls)
        if srv and srv.key not in seen:
            seen.add(srv.key)
            out.append(srv)
    return out