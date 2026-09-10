# SPDX-License-Identifier: MIT
"""Gridly — a tabbed dashboard whose jQuery router writes the URL fragment into
the page with .html(), a DOM-based XSS.

On load and on every hashchange the page runs:

    $('#panel').html(decodeURIComponent(location.hash.slice(1) || 'home'));

`.html()` sets innerHTML. Modern browsers won't execute a bare inline <script>
inserted this way, but an element with an event handler — <img src=x onerror=…>,
<svg onload=…> — runs as soon as it is parsed. The admin bot visits any path you
submit to POST /report while holding its non-HttpOnly `session` cookie, so a
payload that reads document.cookie and beacons it to the collector steals the
admin session. Recover it via GET /oob/received and POST /solve.
"""
import collections
import ipaddress
import json
import os
import urllib.request

from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_QUEUE = 64

app = Flask(__name__)
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)

PAGE = """<!doctype html><html><head><title>Gridly</title>
<script src="/jquery-3.7.1.min.js"></script></head><body>
<h1>Gridly Dashboard</h1>
<nav><a href="#home">Home</a> | <a href="#reports">Reports</a> | <a href="#settings">Settings</a></nav>
<div id="panel">home</div>
<script>
// DELIBERATE DOM XSS: the URL fragment is written into #panel via jQuery .html()
// (innerHTML) with no sanitisation, on load and on every hashchange. A real app
// would use .text() for untrusted routing input.
function render(){ $('#panel').html(decodeURIComponent(location.hash.slice(1) || 'home')); }
$(window).on('hashchange', render);
$(render);
</script>
</body></html>"""


def _from_backend() -> bool:
    try:
        return ipaddress.ip_address(request.remote_addr or "") in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    return Response(PAGE, mimetype="text/html")


@app.get("/jquery-3.7.1.min.js")
def jquery() -> Response:
    try:
        with open(os.path.join(os.path.dirname(__file__), "jquery-3.7.1.min.js"), encoding="utf-8") as fh:
            return Response(fh.read(), mimetype="application/javascript")
    except OSError:
        return Response("// unavailable", mimetype="application/javascript", status=500)


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
