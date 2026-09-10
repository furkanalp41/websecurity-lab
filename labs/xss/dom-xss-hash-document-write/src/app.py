# SPDX-License-Identifier: MIT
"""Nimbus — a static marketing microsite with a DOM-based XSS.

On load, an inline script personalises the greeting straight from the URL
fragment, with no sanitisation:

    document.write('<h1>Welcome ' + decodeURIComponent(location.hash.slice(1)) + '</h1>')

The fragment never reaches the server (it is client-side only), so this is a
pure DOM sink — the payload must run in a browser. The admin bot visits any path
you submit to POST /report while holding its `session` cookie.

The prize is a same-origin resource: GET /flag.txt returns the flag, but only to
a request carrying the admin `session` cookie. You cannot fetch it directly (you
do not have the cookie, and /internal/bot-login is backend-only). But JavaScript
you inject via the DOM XSS runs in the admin bot's origin, so its same-origin
`fetch('/flag.txt')` sends the cookie for you. Exfiltrate the body to the
in-lab collector.
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

# The vulnerable microsite. The inline script writes the URL fragment into the
# document with no encoding — a textbook DOM-based XSS (source: location.hash,
# sink: document.write).
PAGE = """<!doctype html><html><head><title>Nimbus</title></head><body>
<script>
// DELIBERATE DOM XSS: the '#'-fragment is written to the document unsanitised,
// during initial parse. A real site would set textContent, not document.write.
document.write('<h1>Welcome ' + decodeURIComponent(location.hash.slice(1)) + '</h1>');
</script>
<p>Nimbus — cloud storage for humans. Personalise your greeting with #yourname.</p>
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


@app.get("/flag.txt")
def flag_txt() -> Response:
    """Same-origin secret: served ONLY to a request carrying the admin session
    cookie. The public side has no cookie; only JS running in the admin bot's
    origin (via the DOM XSS) can read this."""
    import hmac
    got = request.cookies.get("session", "")
    if ADMIN_SESSION and hmac.compare_digest(got, ADMIN_SESSION):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                return Response(fh.read().strip(), mimetype="text/plain")
        except OSError:
            return Response("(flag unavailable)", mimetype="text/plain", status=500)
    return Response("forbidden — admin session required", status=403, mimetype="text/plain")


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
