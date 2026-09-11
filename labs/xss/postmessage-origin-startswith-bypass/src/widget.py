# SPDX-License-Identifier: MIT
"""Chat-widget origin (stdlib). Serves /frame as a page that postMessages a text
UP to its parent window:

    parent.postMessage(<text>, '*')

This one service answers to several docker-compose network aliases, and it behaves
DIFFERENTLY depending on which host it was reached as (the `Host` header):

  * `widget-host` (the LEGITIMATE origin ChatCo embeds) — sends a FIXED, safe
    message and IGNORES any `?msg=`. So a message from the genuine widget passes
    ChatCo's origin check but carries no attacker payload.
  * any OTHER host — e.g. `widget-host-evil` (a LOOK-ALIKE whose host begins with
    `widget-host`, so it satisfies ChatCo's flawed `startsWith` check) or
    `notwidget` — REFLECTS the attacker-supplied `?msg=`.

This is what makes the prefix-bypass NECESSARY: to deliver a payload the attacker
needs a frame that BOTH reflects `?msg=` AND passes the origin check — only the
look-alike does both (the legit host reflects nothing; `notwidget` reflects but is
rejected). It is mock infra (stdlib, no deps), not the gated lab app.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# The genuine widget origin. Reached as this exact Host, the frame sends only a
# fixed safe message (never reflects ?msg=), so it cannot carry an attacker payload.
LEGIT_WIDGET_HOST = os.environ.get("LEGIT_WIDGET_HOST", "widget-host:8080")
FIXED_SAFE_MSG = "Welcome to ChatCo support."


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, "text/plain", b"ok")
            return
        if parsed.path == "/frame":
            if self.headers.get("Host", "") == LEGIT_WIDGET_HOST:
                # The genuine widget: fixed safe content only, never reflects ?msg=.
                msg = FIXED_SAFE_MSG
            else:
                # A look-alike / other origin reflects the attacker-supplied msg.
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
