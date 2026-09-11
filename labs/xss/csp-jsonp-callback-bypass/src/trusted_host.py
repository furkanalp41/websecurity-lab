# SPDX-License-Identifier: MIT
"""Mock "accounts.trusted" host — the second origin Vaultboard allowlists in its
CSP script-src so it can embed an accounts widget. It exposes a classic **JSONP**
endpoint:

    GET /api/jsonp?callback=<name>   ->   <name>({"authenticated": false, ...})

served as `application/javascript`. The callback name is reflected **verbatim**
into an executable position with no validation (a real JSONP endpoint must accept
only `[A-Za-z0-9_.]` callbacks) — so `callback=<arbitrary JS>//` turns the
response into attacker code. Because this origin is allowlisted in the target's
CSP, a `<script src>` pointing here is permitted, and the JSONP gadget then runs
arbitrary script in the TARGET's origin.

Stdlib only; this is a mock external dependency (infra), not the gated lab app.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, "text/plain", b"ok")
            return
        if parsed.path == "/api/jsonp":
            qs = parse_qs(parsed.query)
            # VERBATIM reflection of the callback name — the deliberate gadget.
            callback = (qs.get("callback") or ["callback"])[0]
            data = json.dumps({"authenticated": False, "user": None})
            body = ("/* accounts widget */\n%s(%s);" % (callback, data)).encode("utf-8")
            self._send(200, "application/javascript", body)
            return
        self._send(404, "text/plain", b"not found")

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
