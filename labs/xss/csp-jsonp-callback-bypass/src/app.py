# SPDX-License-Identifier: MIT
"""Vaultboard — a notes app that reflects the ?q= search term into the page with
NO HTML escaping, and relies entirely on a Content-Security-Policy to neuter the
resulting HTML injection. The CSP forbids inline script and inline event handlers
(no 'unsafe-inline' in script-src), so a reflected `<script>alert(1)</script>` or
`<img onerror=...>` does NOT run — the CSP holds against the obvious payloads.

The flaw is the CSP's script-src ALLOWLIST: it trusts a second origin,
`http://accounts-trusted:8080`, so that Vaultboard can embed the accounts widget.
That trusted host exposes a JSONP endpoint, `/api/jsonp?callback=<name>`, which
reflects the callback name verbatim into an executable position. An attacker
combines the two: reflect a `<script src="http://accounts-trusted:8080/api/jsonp
?callback=<JS>">` — the script SOURCE is allowlisted, so the CSP permits it, and
the JSONP endpoint turns `<JS>` into code that runs in Vaultboard's origin with
the admin's non-HttpOnly session cookie.

The admin bot (shared xss-verifier headless Chromium) logs in via
/internal/bot-login and visits any path queued through POST /report.
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
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
# The origin Vaultboard trusts for scripts (the "accounts" widget host). It is an
# allowlisted script-src, and it happens to expose a JSONP callback endpoint.
TRUSTED_SCRIPT_ORIGIN = os.environ.get("TRUSTED_SCRIPT_ORIGIN", "http://accounts-trusted:8080")
MAX_QUEUE = 64

app = Flask(__name__)
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)

# Autoescape OFF: q is reflected raw. In this lab the app "knows" that and leans on
# the CSP below to contain any injected markup — which is exactly the misplaced
# trust the lab is about.
_unsafe_env = Environment(autoescape=False)  # noqa: S701 — reflection is contained by CSP (the lesson)

PAGE = _unsafe_env.from_string(
    """<!doctype html><html><head><title>Vaultboard</title></head><body>
<h1>Vaultboard</h1>
<form action="/" method="get">
  <input name="q" placeholder="search your notes" value="">
  <button type="submit">Search</button>
</form>
{% if q is not none %}<div class="results">Results for {{ q }}</div>
<p>No notes matched.</p>{% endif %}
<hr><small>Found a broken page? <a href="/report-help">Report it to staff.</a></small>
</body></html>"""
)


def _csp() -> str:
    # Blocks inline script and inline event handlers (no 'unsafe-inline' in
    # script-src) — so the reflected HTML injection cannot run script directly.
    # The hole is the allowlisted TRUSTED_SCRIPT_ORIGIN in script-src.
    return (
        "default-src 'self'; "
        "script-src 'self' " + TRUSTED_SCRIPT_ORIGIN + "; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src * data:; "
        "connect-src *; "
        "base-uri 'none'; "
        "object-src 'none'"
    )


@app.after_request
def set_csp(resp: Response) -> Response:
    resp.headers["Content-Security-Policy"] = _csp()
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
    q = request.args.get("q")
    return Response(PAGE.render(q=q), mimetype="text/html")


@app.get("/report-help")
def report_help() -> Response:
    return Response(
        "<!doctype html><h1>Report a page</h1>"
        "<p>POST /report with form field <code>url</code> (a path on this site). "
        "Our staff reviews reported pages automatically.</p>",
        mimetype="text/html",
    )


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
