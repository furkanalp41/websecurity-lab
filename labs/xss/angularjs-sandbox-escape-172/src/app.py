# SPDX-License-Identifier: MIT
"""Checkout Confirm — a checkout confirmation page bootstrapped with AngularJS
1.7.2 (``ng-app``) that reflects the ``?name=`` query parameter, **HTML-escaped**,
into the *text* of the Angular-compiled region.

HTML-escaping is the reflex fix for reflected XSS: it turns ``<script>`` into
inert ``&lt;script&gt;``. But it does **nothing** to stop AngularJS, which parses
``{{ ... }}`` interpolation out of the text nodes it compiles — on the *decoded*
DOM, after the browser has already turned ``&quot;``/``&#x27;`` back into real
quotes. AngularJS 1.6+ removed the expression sandbox, so a
``{{ constructor.constructor("…")() }}`` gadget reaches the ``Function``
constructor and runs arbitrary JavaScript. This is client-side template
injection (CSTI).

The victim is an admin bot (the shared xss-verifier headless Chromium) that:
  * logs in via GET /internal/bot-login?k=<BOT_KEY> — the app Set-Cookies the
    admin ``session`` cookie (non-HttpOnly, so ``document.cookie`` can read it),
    then
  * polls GET /internal/queue for paths submitted through the public POST
    /report form and visits each one carrying that cookie.

A ``{{}}`` payload reflected into the ng-app region therefore evaluates in the
admin's browser with the admin cookie in scope. Exfiltrate it to the in-lab
collector; read it back through GET /oob/received (the collector sits on the
egress-dropped backend network); submit it to POST /solve for the flag.
"""
import collections
import html
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
# /internal/* endpoints are firewalled to the internal backend subnet: the admin
# bot lives there, but the public (edge/published-port) side does NOT, so a lab
# visitor cannot request the admin cookie or read the bot queue directly. This is
# what forces the intended CSTI path instead of a trivial cookie fetch.
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

# The confirmation page. The ONLY dynamic part is the customer name, which is
# HTML-escaped and dropped into the *text* of the <div ng-app> region. Escaping
# neutralises tag/attribute injection (<script>, event handlers) — but the region
# is compiled by AngularJS, and Angular evaluates {{ }} interpolation out of the
# decoded text, so an escaped {{ constructor.constructor(...)() }} still runs.
# The vendored framework (/vendor/lib.min.js) is AngularJS 1.7.2, whose 1.6+
# lineage ships WITHOUT the old expression sandbox — the deliberate flaw.
_PAGE_HEAD = """<!doctype html><html><head><meta charset="utf-8">
<title>Checkout — Order Confirmed</title>
<script src="/vendor/lib.min.js"></script>
</head><body>
<h1>Checkout</h1>
<div ng-app>
  <p>Order confirmed for """
_PAGE_TAIL = """. Thank you for shopping with us.</p>
</div>
<hr><small>Wrong name on your receipt? <a href="/report-help">Report this page to our staff.</a></small>
</body></html>"""


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    # DELIBERATE VULNERABILITY (CSTI): the customer name is HTML-escaped — which
    # stops <script>/attribute injection — and then reflected into the text of an
    # AngularJS-compiled region. The browser decodes the entities into a text
    # node before AngularJS parses it, so an escaped {{ }} expression (quotes and
    # all) survives to be evaluated client-side. Escaping is NOT a defence here.
    name = request.args.get("name")
    if not name:
        name = "valued customer"
    reflected = html.escape(name)  # quote=True → " and ' become entities too
    return Response(_PAGE_HEAD + reflected + _PAGE_TAIL, mimetype="text/html")


@app.get("/vendor/lib.min.js")
def vendor_lib() -> Response:
    """Serve the vendored AngularJS 1.7.2 framework from disk (placed next to this
    module at build time). Mirrors how dom-xss-innerhtml-jquery-html serves its
    jQuery file. This lab intentionally ships an END-OF-LIFE framework version —
    that sandbox-less version IS the vulnerability; it must not be 'upgraded'."""
    try:
        with open(os.path.join(os.path.dirname(__file__), "lib.min.js"), encoding="utf-8") as fh:
            return Response(fh.read(), mimetype="application/javascript")
    except OSError:
        return Response("// unavailable", mimetype="application/javascript", status=500)


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
