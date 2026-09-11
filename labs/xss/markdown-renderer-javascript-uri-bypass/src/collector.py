# SPDX-License-Identifier: MIT
"""OOB collector sidecar for reflected-xss-search-noescape (stdlib only).

Listens on :9000. Any GET/POST to any path is stored (path + method + raw body)
and retrievable via GET /received (JSON). The XSS payload run by the admin bot
beacons the stolen cookie here as GET /report?c=<document.cookie>. The collector
sits on the internal, egress-dropped `backend` network, so it is the only
listener a payload can reach — the app proxies it via GET /oob/received.
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LOCK = threading.Lock()
_STORE: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    def _capture(self, method: str) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        with _LOCK:
            _STORE.append({
                "method": method, "path": self.path, "length": len(body),
                "body_b64": base64.b64encode(body).decode(),
            })

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, "text/plain", b"ok"); return
        if self.path == "/received":
            with _LOCK:
                payload = json.dumps({"count": len(_STORE), "items": _STORE}).encode()
            self._send(200, "application/json", payload); return
        if self.path == "/reset":
            with _LOCK:
                _STORE.clear()
            self._send(200, "text/plain", b"cleared"); return
        self._capture("GET")
        self._send(200, "text/plain", b"ok")

    def do_POST(self) -> None:  # noqa: N802
        self._capture("POST")
        self._send(200, "text/plain", b"ok")

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()


if __name__ == "__main__":
    main()
