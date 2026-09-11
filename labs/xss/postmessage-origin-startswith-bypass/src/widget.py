# SPDX-License-Identifier: MIT
"""Chat-widget origin (stdlib). Serves /frame?msg=<text> as a page that
postMessages <text> UP to its parent window:

    parent.postMessage(<msg>, '*')

This one service is given TWO network aliases in docker-compose:
  * `widget-host`      — the legitimate widget origin ChatCo embeds by default;
  * `widget-host-evil` — a LOOK-ALIKE origin whose host begins with `widget-host`,
                         so it satisfies ChatCo's flawed `startsWith` origin check.

The message text is whatever the iframe URL's `msg` param carries, so the frame is
a faithful stand-in for "an attacker page on a look-alike origin that messages the
opener/parent". It is mock infra (stdlib, no deps), not the gated lab app.
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
        if parsed.path == "/frame":
            msg = (parse_qs(parsed.query).get("msg") or [""])[0]
            # json.dumps → a safe JS string literal; the raw text is delivered to
            # the parent's message handler verbatim as event.data.
            page = (
                "<!doctype html><html><body><script>"
                "try{ parent.postMessage(%s, '*'); }catch(e){}"
                "</script>chat widget</body></html>"
            ) % json.dumps(msg)
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
