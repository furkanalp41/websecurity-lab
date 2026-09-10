# SPDX-License-Identifier: MIT
"""OpsConsole — an ops status site whose admin "visitor access log" panel renders
each stored request User-Agent with **no HTML escaping** (blind stored XSS).

The vulnerability is BLIND: `GET /` records the raw `User-Agent` header of every
public request into an in-process ring buffer, but never reflects it back to the
sender. The attacker therefore gets no feedback that the payload landed — it lies
dormant until the privileged admin views the log.

The victim is an admin bot (the shared xss-verifier headless Chromium) that:
  * logs in via GET /internal/bot-login?k=<BOT_KEY> — the app Set-Cookies the
    admin `session` cookie (non-HttpOnly, samesite=Lax), then
  * loads its FIXED_URL GET /admin/logs every couple of seconds carrying that
    cookie. That admin-only page renders each stored User-Agent through an
    autoescape-DISABLED Jinja environment (the |safe-equivalent) — the sink.

A stored `<img onerror>` User-Agent therefore executes in the admin's browser
when the bot renders the log. There is no cookie to read here (the interesting
secret is an API key behind another admin-only route), so the payload chains:
`fetch('/admin/apikey')` runs same-origin with the admin cookie in scope, reads
the key, and beacons it to the in-lab collector. Read it back through
GET /oob/received (the collector sits on the egress-dropped backend network);
submit it to POST /solve for the flag.
"""
import collections
import hmac
import ipaddress
import json
import os
import urllib.request

from flask import Flask, Response, request
from jinja2 import Environment

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
# /internal/* endpoints are firewalled to the internal backend subnet: the admin
# bot lives there, but the public (edge/published-port) side does NOT, so a lab
# visitor cannot mint the admin cookie or read the admin API key directly. This is
# what forces the intended blind-XSS path instead of a trivial fetch.
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_LOG = 50

app = Flask(__name__)


def _from_backend() -> bool:
    try:
        peer = ipaddress.ip_address(request.remote_addr or "")
        return peer in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


def _is_admin() -> bool:
    """The admin API key / log panel are gated on the admin session cookie the bot
    holds. Constant-time compare so the gate cannot be timing-oracle'd."""
    return bool(ADMIN_SESSION) and hmac.compare_digest(
        request.cookies.get("session", ""), ADMIN_SESSION
    )


# Single-worker, in-process ring buffer of the most recent visitor User-Agents.
_log: collections.deque = collections.deque(maxlen=MAX_LOG)

# Infrastructure / admin routes are not part of the "visitor access log" and are
# excluded so the bot's own polling (bot-login + the log read) and the health
# probe do not flood the buffer and evict the stored payload.
_SKIP_LOG = ("/health", "/admin", "/internal", "/oob", "/solve", "/favicon.ico")


@app.before_request
def _record_ua() -> None:
    """Every PUBLIC request's raw User-Agent header is appended to the log. It is
    stored verbatim (the stored-XSS source) and never reflected to the sender —
    that absence of feedback is exactly what makes this XSS *blind*."""
    path = request.path or "/"
    if path.startswith(_SKIP_LOG):
        return
    _log.append(request.headers.get("User-Agent", ""))


# DELIBERATE VULNERABILITY: an autoescape-disabled Jinja environment renders the
# admin log table, so each stored User-Agent is interpolated into HTML raw. A real
# app leaves Jinja's autoescape ON; this lab mimics a panel switched off "so the
# raw UA string shows verbatim" — the canonical stored-XSS footgun, here on an
# HTTP header sink most input-validation overlooks.
_unsafe_env = Environment(autoescape=False)  # noqa: S701 — the taught flaw

LOGS_PAGE = _unsafe_env.from_string(
    """<!doctype html><html><head><title>OpsConsole — Access Log</title></head><body>
<h1>Visitor Access Log</h1>
<p>Most recent {{ entries|length }} visitor user-agents (newest last).</p>
<table border="1" cellpadding="4"><thead><tr><th>#</th><th>User-Agent</th></tr></thead>
<tbody>
{% for ua in entries %}<tr><td>{{ loop.index }}</td><td class="ua">{{ ua }}</td></tr>
{% endfor %}</tbody></table>
<hr><small>OpsConsole staff panel. API key at <a href="/admin/apikey">/admin/apikey</a>.</small>
</body></html>"""
)

# The public landing page. Note it renders NOTHING attacker-controlled: the stored
# User-Agent is not echoed here, which is what makes the sink blind.
HOME_PAGE = (
    "<!doctype html><html><head><title>OpsConsole</title></head><body>"
    "<h1>OpsConsole</h1>"
    "<p>All systems operational. This is the public status page.</p>"
    "<p>Staff: the visitor access log is at <a href=\"/admin/logs\">/admin/logs</a> "
    "(staff session required).</p>"
    "</body></html>"
)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    # The request User-Agent has already been logged by _record_ua(); the response
    # deliberately does not include it (blind).
    return Response(HOME_PAGE, mimetype="text/html")


@app.get("/admin/logs")
def admin_logs() -> Response:
    """Admin-only visitor access log. VULNERABILITY: each stored User-Agent is
    rendered through the autoescape-disabled environment, so stored markup runs in
    the admin's browser. Gated on the admin session so only the bot can load it."""
    if not _is_admin():
        return Response("forbidden — admin only", status=403, mimetype="text/plain")
    return Response(LOGS_PAGE.render(entries=list(_log)), mimetype="text/html")


@app.get("/admin/apikey")
def admin_apikey() -> Response:
    """Admin-only: returns the console API key (== the admin session value) as
    plain text. Same-origin script running in the admin's browser can read it;
    a public visitor gets 403. This is what the blind-XSS payload exfiltrates."""
    if not _is_admin():
        return Response("forbidden — admin only", status=403, mimetype="text/plain")
    return Response(ADMIN_SESSION, mimetype="text/plain")


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
    # NON-HttpOnly on purpose: it mirrors the storefront's real cookie so the
    # /admin/apikey fetch inherits it. HttpOnly would not even help here — the key
    # is stolen via fetch(), not document.cookie — the real fix is output encoding.
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
    # The payload may exfiltrate the raw key or a "session=<value>" cookie string;
    # accept either the bare value or the name=value form.
    if submitted.startswith("session="):
        submitted = submitted[len("session="):]
    if "; " in submitted:
        submitted = submitted.split("; ", 1)[0]
    if ADMIN_SESSION and hmac.compare_digest(submitted, ADMIN_SESSION):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(json.dumps({"ok": True, "flag": flag}), mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "that is not the admin api key"}),
                    mimetype="application/json", status=403)
