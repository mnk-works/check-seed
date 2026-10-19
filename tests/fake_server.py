"""Local fake Electrum server used to prove cross-checking catches a lying server.

These bind to 127.0.0.1 on ephemeral ports and speak just enough of the protocol
to answer version/ping/listunspent. No network access and no keys involved.
"""

from __future__ import annotations

import json
import socket
import threading


class FakeElectrum:
    """Answers with `fake_value` sats for every listunspent, honestly or not."""

    def __init__(self, fake_value: int = 0, honest: bool = True) -> None:
        self.fake_value = fake_value
        self.honest = honest
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.queries: list[str] = []
        self.version_calls = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                self._handle(conn)
            finally:
                conn.close()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(3)
        buf = b""
        try:
            while not self._stop.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        req = json.loads(line.decode())
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        return
                    if not self._respond(conn, req):
                        return
        except OSError:
            return

    def _respond(self, conn: socket.socket, req: dict) -> bool:
        method = req.get("method")
        rid = req.get("id")
        params = req.get("params") or []

        if method == "server.version":
            # Real ElectrumX/Fulcrum allow server.version exactly once per
            # connection and reject a second with "server.version already done".
            if self.version_calls:
                payload = json.dumps({
                    "jsonrpc": "2.0", "id": rid,
                    "error": {"code": 1, "message": "server.version already done"},
                })
                try:
                    conn.sendall(payload.encode() + b"\n")
                except OSError:
                    return False
                return True
            self.version_calls += 1
            result = ["FakeElectrum 0.1", "1.4"]
        elif method == "server.ping":
            result = None
        elif method == "blockchain.scripthash.listunspent":
            self.queries.append(params[0])
            if self.honest:
                result = []
            else:
                result = [{
                    "tx_hash": "00" * 32,
                    "tx_pos": 0,
                    "height": 100,
                    "value": self.fake_value,
                }]
        else:
            result = None

        payload = json.dumps({"jsonrpc": "2.0", "id": rid, "result": result})
        try:
            conn.sendall(payload.encode() + b"\n")
        except OSError:
            return False
        return True

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass