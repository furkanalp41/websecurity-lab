# SPDX-License-Identifier: MIT
"""ChatCo — a support site whose host page embeds a chat widget in an iframe and
receives messages from it via window.postMessage. The message handler checks the
sender's origin with a **prefix** test:

    if (e.origin.startsWith('http://widget-host')) slot.innerHTML = e.data;

That is the flaw: `startsWith` has no delimiter, so any origin whose host BEGINS
with `widget-host` — e.g. `http://widget-host-evil:8080` — passes the check. A
page on such a look-alike origin can postMessage arbitrary HTML into `slot`, and
because the handler runs in ChatCo's own (authenticated) top-level page, an
`<img onerror>` in that HTML executes with the admin's non-HttpOnly session cookie.

Design note (sound delivery): the admin bot loads ChatCo TOP-LEVEL (so its Lax
session cookie is present), and the host page embeds the attacker's iframe via a
`?widget=` parameter (escaped into the src, so there is no attribute-breakout
shortcut). The attacker iframe — on the look-alike origin — postMessages the
payload UP to the top-level handler. The sink therefore runs in the authenticated
top-level document, not in a cross-site iframe (where a Lax cookie would be
absent). See SOLUTION for why the "attacker frames the target" topology fails here.
"""
import collections
import hmac
import html
import ipaddress
import json
import os
import urllib.parse
import urllib.request

from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
# The legit widget origin embedded by default, and the FLAWED prefix the message
# handler checks the sender origin against (no delimiter → prefix-extension bypass).
WIDGET_ORIGIN = os.environ.get("WIDGET_ORIGIN", "http://widget-host:8080")
TRUSTED_PREFIX = os.environ.get("TRUSTED_ORIGIN_PREFIX", "http://widget-host")
MAX_QUEUE = 64

app = Flask(__name__)
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)


def _from_backend() -> bool:
    try:
        return ipaddress.ip_address(request.remote_addr or "") in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


def _page(widget_url: str) -> str:
    # widget_url is attacker-influenceable (?widget=) → HTML-escape it into the
    # src attribute so there is no attribute breakout. The ONLY way in is the
    # postMessage origin-check bypass.
    safe_src = html.escape(widget_url, quote=True)
    prefix_js = json.dumps(TRUSTED_PREFIX)  # safe JS string literal
    return (
        "<!doctype html><html><head><title>ChatCo Support</title></head><body>"
        "<h1>ChatCo Support</h1>"
        "<p>Our chat widget loads below.</p>"
        "<iframe id=\"widget\" src=\"%s\" width=\"320\" height=\"200\"></iframe>"
        "<div id=\"slot\">No messages yet.</div>"
        "<script>"
        "window.addEventListener('message', function(e){"
        # THE FLAW: a prefix test with no delimiter. 'http://widget-host-evil:8080'
        # begins with 'http://widget-host', so a look-alike origin is accepted.
        "  if (e.origin.indexOf(%s) === 0) {"
        "    document.getElementById('slot').innerHTML = e.data;"
        "  }"
        "});"
        "</script>"
        "</body></html>"
    ) % (safe_src, prefix_js)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    widget = request.args.get("widget", "")
    if not widget:
        widget = WIDGET_ORIGIN + "/frame?msg=" + urllib.parse.quote("Welcome to ChatCo support.")
    return Response(_page(widget), mimetype="text/html")


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
    resp.set_cookie("session", ADMIN_SESSION, httponly=False, samesite="Lax")
    return resp


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
    body = request.get_json(silent=True) or {}
    submitted = str(body.get("c", "")).strip()
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
    return Response(json.dumps({"ok": False, "error": "that is not the admin session"}),
                    mimetype="application/json", status=403)
