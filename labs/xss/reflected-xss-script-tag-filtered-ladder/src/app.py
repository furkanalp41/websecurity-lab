# SPDX-License-Identifier: MIT
"""HelpDesk Lite — a support-ticket form whose preview page reflects the
`?subject=` parameter into a visible ``<div class="subject">...</div>`` after a
naive **single-pass substring blocklist** filter, with **no HTML escaping**
(reflected XSS behind an incomplete denylist).

The filter (`_filter`) removes, case-insensitively and in ONE left-to-right pass,
each of the substrings ``<script``, ``</script``, ``javascript:`` and
``onerror=``. Every token is stripped exactly once — the result is **never
re-scanned** (no loop to a fixpoint) — and the surviving value is then reflected
into the page **raw**. The blocklist is incomplete by design: it never considers
``<svg>``/``<img>`` with ``onload``, event handlers other than ``onerror``, or
``onerror`` with whitespace before the ``=`` — so several payloads sail straight
through and fire script in the victim's browser.

The victim is an admin bot (the shared xss-verifier headless Chromium) that:
  * logs in via GET /internal/bot-login?k=<BOT_KEY> — the app Set-Cookies the
    admin `session` cookie (non-HttpOnly, so document.cookie can read it — the
    misconfiguration the cookie-theft turns on), then
  * polls GET /internal/queue for URLs submitted through the public POST /report
    form and visits each one carrying that cookie.

A payload that bypasses the blocklist therefore runs in the admin's browser with
the admin cookie in scope. Exfiltrate it to the in-lab collector; read it back
through GET /oob/received (the collector sits on the egress-dropped backend
network); submit it to POST /solve for the flag.
"""
import collections
import ipaddress
import json
import os
import re
import urllib.request

from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
# /internal/* endpoints are firewalled to the internal backend subnet: the admin
# bot lives there, but the public (edge/published-port) side does NOT, so a lab
# visitor cannot request the admin cookie or read the bot queue directly. This is
# what forces the intended reflected-XSS path instead of a trivial cookie fetch.
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_QUEUE = 64

app = Flask(__name__)


def _from_backend() -> bool:
    try:
        peer = ipaddress.ip_address(request.remote_addr or "")
        return peer in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


# Single-worker, in-process queue of paths the admin bot has yet to visit.
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)

# DELIBERATE VULNERABILITY: a naive single-pass substring blocklist "sanitiser".
# Each token below is stripped exactly once, left-to-right, with NO re-scan of
# the result (no loop to a fixpoint) and NO output encoding afterwards — the
# surviving value is reflected into the HTML body raw. The blocklist is
# incomplete by design; see _filter and SOLUTION.md for the bypass ladder.
_BLOCKLIST = ("<script", "</script", "javascript:", "onerror=")


def _filter(value: str) -> str:
    """Remove each blocked token once, case-insensitively, in a single pass.

    `re.sub` with no `count` strips every non-overlapping occurrence of the
    token in ONE scan; we then move to the next token. Crucially we do NOT loop
    the whole thing to a fixpoint, so:
      * an inner blocked token nested inside a split outer copy — e.g.
        ``<scr<scriptipt>`` — survives as ``<script>`` once the inner copy is
        deleted (the result is never re-scanned), and
      * anything the list never names (``<svg onload>``, ``onload=``,
        ``onpointerenter=``, ``onerror`` with whitespace before ``=``) passes
        through untouched.
    """
    for tok in _BLOCKLIST:
        value = re.sub(re.escape(tok), "", value, flags=re.IGNORECASE)
    return value


def render_page(subject: "str | None") -> str:
    """Build the support page. When `subject` is present it is filtered and then
    reflected RAW into a visible <div class="subject"> (the taught sink)."""
    if subject is None:
        preview = ""
    else:
        reflected = _filter(subject)  # single-pass blocklist, then raw reflection
        preview = (
            '<h2>Ticket preview</h2>\n'
            '<div class="subject">' + reflected + "</div>\n"
            "<p>A support agent will review your ticket shortly.</p>"
        )
    return (
        "<!doctype html><html><head><title>HelpDesk Lite</title></head><body>\n"
        "<h1>HelpDesk Lite &mdash; open a support ticket</h1>\n"
        '<form action="/" method="get">\n'
        '  <input name="subject" placeholder="subject line" value="">\n'
        '  <button type="submit">Preview ticket</button>\n'
        "</form>\n" + preview + "\n"
        '<hr><small>Wrong page? <a href="/report-help">Report a page to our '
        "support staff.</a></small>\n"
        "</body></html>"
    )


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    subject = request.args.get("subject")  # None when absent → preview hidden
    return Response(render_page(subject), mimetype="text/html")


@app.get("/report-help")
def report_help() -> Response:
    return Response(
        "<!doctype html><h1>Report a page</h1>"
        "<p>POST /report with form field <code>url</code> (a path on this site). "
        "Our support staff reviews reported pages automatically.</p>",
        mimetype="text/html",
    )


@app.post("/report")
def report() -> Response:
    """Public: queue a path for the admin bot to review. Accepts form or JSON."""
    url = ""
    if request.is_json:
        url = str((request.get_json(silent=True) or {}).get("url", ""))
    if not url:
        url = request.form.get("url", "")
    url = url.strip()
    if not url:
        return Response(json.dumps({"ok": False, "error": "url required"}),
                        mimetype="application/json", status=400)
    # Only same-site paths are queued; the bot prepends its own origin.
    if url.startswith("http://") or url.startswith("https://"):
        return Response(json.dumps({"ok": False, "error": "submit a path, not a full URL"}),
                        mimetype="application/json", status=400)
    if not url.startswith("/"):
        url = "/" + url
    _queue.append(url)
    return Response(json.dumps({"ok": True, "queued": url}), mimetype="application/json")


@app.get("/internal/queue")
def internal_queue() -> Response:
    """Bot-only (backend network): drain and return pending paths."""
    if not _from_backend():
        return Response("forbidden", status=403, mimetype="text/plain")
    urls = []
    while _queue:
        urls.append(_queue.popleft())
    return Response(json.dumps({"urls": urls}), mimetype="application/json")


@app.get("/internal/bot-login")
def bot_login() -> Response:
    """Bot-only: mint the admin session cookie into the bot's browser. Gated both
    to the backend network AND by a shared BOT_KEY so a lab visitor on the public
    side cannot simply request the admin cookie via Set-Cookie."""
    if not _from_backend():
        return Response("forbidden", status=403, mimetype="text/plain")
    if not BOT_KEY or request.args.get("k", "") != BOT_KEY:
        return Response("forbidden", status=403, mimetype="text/plain")
    resp = Response("logged in", mimetype="text/plain")
    # NON-HttpOnly on purpose: document.cookie must be able to read it. HttpOnly
    # here would defeat the exfiltration and is a primary defence (see SOLUTION).
    resp.set_cookie("session", ADMIN_SESSION, httponly=False, samesite="Lax")
    return resp


@app.get("/oob/received")
def oob_received() -> Response:
    """App-side proxy to the in-lab collector (which is on the internal,
    egress-dropped backend network and not otherwise reachable)."""
    try:
        with urllib.request.urlopen(
            f"http://{OOB_HOST}:{OOB_PORT}/received", timeout=5
        ) as r:
            body = r.read()
    except Exception as e:  # noqa: BLE001
        return Response(json.dumps({"ok": False, "error": str(e)}),
                        mimetype="application/json", status=502)
    return Response(body, mimetype="application/json")


@app.post("/solve")
def solve() -> Response:
    body = request.get_json(silent=True) or {}
    submitted = str(body.get("c", "")).strip()
    # The payload may exfiltrate the whole "session=<value>" cookie string; accept
    # either the bare value or the name=value form.
    if submitted.startswith("session="):
        submitted = submitted[len("session="):]
    if "; " in submitted:
        submitted = submitted.split("; ", 1)[0]
    import hmac
    if ADMIN_SESSION and hmac.compare_digest(submitted, ADMIN_SESSION):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(json.dumps({"ok": True, "flag": flag}), mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "that is not the admin session"}),
                    mimetype="application/json", status=403)
