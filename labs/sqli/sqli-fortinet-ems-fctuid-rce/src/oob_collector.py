# SPDX-License-Identifier: MIT
"""Custom OOB collector sidecar (stdlib only).

Listens on :9000. Anything POSTed to any path is stored (path -> raw bytes) and
retrievable later with GET /received (JSON list). The app has a proxy endpoint,
GET /oob/received, that fetches from this collector — the RCE targets sit on a
no-egress `backend` network, so this is the ONLY listener they can reach.
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


_LOCK = threading.Lock()
_STORE: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, "text/plain", b"ok")
            return
        if self.path == "/received":
            with _LOCK:
                payload = json.dumps({"count": len(_STORE), "items": _STORE}).encode()
            self._send(200, "application/json", payload)
            return
        if self.path == "/reset":
            with _LOCK:
                _STORE.clear()
            self._send(200, "text/plain", b"cleared")
            return
        self._send(404, "text/plain", b"not found")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        with _LOCK:
            _STORE.append({
                "path": self.path,
                "length": len(body),
                # Store raw bytes as base64 so the JSON survives non-utf8 payloads
                # (the RCE writes hex/bytes, not necessarily text).
                "body_b64": base64.b64encode(body).decode(),
            })
        self._send(200, "text/plain", b"ok")

    def log_message(self, fmt: str, *args) -> None:  # quiet the default access log
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
