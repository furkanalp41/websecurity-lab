# SPDX-License-Identifier: MIT
"""Relaydash — a dashboard whose CSP restricts scripts with a per-response NONCE
(`script-src 'nonce-<random>'`, no 'self', no 'unsafe-inline') but OMITS the
`base-uri` directive. The dashboard loads its bundle with a RELATIVE, nonced path,
`<script src="main.js" nonce="<random>">`, and reflects a `?ref=` value into <head>
unescaped (a single-tag HTML injection) ABOVE that script.

The nonce is what makes this lab specifically about base-uri. An attacker cannot
inject their OWN script: an inline `<script>`, an `<img onerror>`, or even a
`<script src="/u/<id>/main.js">` pointing at same-origin attacker content is all
BLOCKED, because none of them carry the per-response nonce (and there is no 'self'
in script-src to fall back on). The only script the CSP trusts is the page's own
nonced `<script src="main.js">`.

But with no `base-uri` restriction, an injected `<base href="/u/<id>/">` changes
the document base URL, so that trusted, nonced `main.js` now resolves to
`/u/<id>/main.js` — attacker-uploaded content. The nonce travels with the ELEMENT,
not the URL, so the redirected script loads with a valid nonce and executes in the
dashboard's origin with the admin's non-HttpOnly session cookie in scope.

The admin bot logs in via /internal/bot-login and visits any path queued through
POST /report.
"""
import collections
import hmac
import ipaddress
import json
import os
import secrets
import urllib.request

from flask import Flask, Response, g, request
from jinja2 import Environment

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_QUEUE = 64
MAX_UPLOADS = 64

app = Flask(__name__)
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)
# Attacker-uploadable scripts, served SAME-ORIGIN under /u/<id>/main.js. This is
# the "user content on your own origin" gadget that base-uri hijacking turns into
# script execution — a stand-in for uploaded files / a CDN path / a JSONP echo.
_uploads: "collections.OrderedDict[str, str]" = collections.OrderedDict()

# Autoescape OFF for the <head> reflection: ref is reflected raw. The app relies on
# the CSP to contain it (which it does for inline vectors — the missing base-uri is
# the actual hole).
_unsafe_env = Environment(autoescape=False)  # noqa: S701 — contained by CSP except for base-uri

PAGE = _unsafe_env.from_string(
    """<!doctype html><html><head>
<title>Relaydash</title>
{{ ref }}
<script src="main.js" nonce="{{ nonce }}"></script>
</head><body>
<h1>Relaydash</h1>
<p>Your relays load below.</p>
<div id="app">loading…</div>
</body></html>"""
)

# The legitimate bundle (benign). With the base-uri hijack it is never reached;
# the attacker's /u/<id>/main.js loads instead.
LEGIT_MAIN_JS = "document.getElementById('app').textContent='No relays configured.';"


def _csp(nonce: str) -> str:
    # NONCE-based script-src, NO 'self' and NO 'unsafe-inline': inline script,
    # onerror handlers, AND a directly-injected <script src="/u/<id>/main.js"> are
    # all blocked — none carry this per-response nonce. The only trusted script is
    # the page's own nonced <script src="main.js">.
    # NOTE: no `base-uri` directive — the deliberate hole. Adding `base-uri 'none'`
    # (or 'self') would neutralise the <base> injection (see SOLUTION).
    return (
        "default-src 'self'; "
        "script-src 'nonce-" + nonce + "'; "
        "img-src * data:; "
        "connect-src *; "
        "style-src 'self' 'unsafe-inline'; "
        "object-src 'none'"
    )


@app.before_request
def _gen_nonce() -> None:
    # Fresh, unguessable per request → an attacker cannot pre-inject a nonced script.
    g.nonce = secrets.token_urlsafe(16)


@app.after_request
def set_csp(resp: Response) -> Response:
    resp.headers["Content-Security-Policy"] = _csp(getattr(g, "nonce", ""))
    return resp


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
    ref = request.args.get("ref", "")
    return Response(PAGE.render(ref=ref, nonce=g.nonce), mimetype="text/html")


@app.get("/main.js")
def main_js() -> Response:
    return Response(LEGIT_MAIN_JS, mimetype="application/javascript")


@app.post("/upload")
def upload() -> Response:
    """Public: store a script served SAME-ORIGIN at /u/<id>/main.js. Model of a
    user-content path on your own origin — harmless on its own, lethal once a
    <base> can point the app's relative <script src> at it."""
    js = ""
    if request.is_json:
        js = str((request.get_json(silent=True) or {}).get("js", ""))
    if not js:
        js = request.form.get("js", "")
    if not js:
        return Response(json.dumps({"ok": False, "error": "js required"}),
                        mimetype="application/json", status=400)
    uid = secrets.token_hex(8)
    _uploads[uid] = js
    while len(_uploads) > MAX_UPLOADS:
        _uploads.popitem(last=False)
    return Response(json.dumps({"ok": True, "id": uid, "path": "/u/%s/main.js" % uid}),
                    mimetype="application/json")


@app.get("/u/<uid>/main.js")
def serve_upload(uid: str) -> Response:
    js = _uploads.get(uid)
    if js is None:
        return Response("// not found", status=404, mimetype="application/javascript")
    return Response(js, mimetype="application/javascript")


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
