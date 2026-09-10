# SPDX-License-Identifier: MIT
"""QuickCart — a checkout page with a reflected XSS in a **JavaScript string
literal**.

`GET /?promo=<v>` echoes the promo code into an *inline* `<script>` block that is
built by string concatenation:

    var promo = '<FILTERED>'; document.getElementById('promo').innerText = promo;

The only "sanitisation" is a naive HTML angle-bracket strip: every `<` and `>`
is removed from the value. That does nothing in a JS-string context — single
quotes and backslashes pass through untouched, so a value beginning with `'`
closes the string literal early and the rest is parsed as live JavaScript. This
is the taught flaw: an HTML-only filter is the wrong encoder for a script
context.

The victim is an admin bot (the shared xss-verifier headless Chromium) that:
  * logs in via GET /internal/bot-login?k=<BOT_KEY> — the app Set-Cookies the
    admin `session` cookie (non-HttpOnly), then
  * polls GET /internal/queue for paths submitted through the public POST /report
    form and visits each one carrying that cookie.

A reflected script therefore runs in the admin's browser. It does a same-origin
credentialed `fetch('/api/whoami')` — which reveals the admin session token only
to a request that already carries the admin cookie — and beacons the JSON to the
in-lab collector. Read it back through GET /oob/received (the collector sits on
the egress-dropped backend network); submit the token to POST /solve for the flag.
"""
import collections
import hmac
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


# DELIBERATE VULNERABILITY: the promo value is concatenated straight into a
# single-quoted JavaScript string literal inside an inline <script>. The only
# filtering is _strip_angles() below — an HTML angle-bracket strip. It is the
# WRONG encoder for this context: a JS string is broken out of with a single
# quote, not an angle bracket, and quotes/backslashes are left untouched.
PAGE_PRE = """<!doctype html><html><head><title>QuickCart Checkout</title></head><body>
<h1>QuickCart - Checkout</h1>
<p>Order #4021 &middot; total <strong>$38.00</strong></p>
<p>Applied promo code: <span id="promo"></span></p>
<form action="/" method="get">
  <input name="promo" placeholder="promo code" value="">
  <button type="submit">Apply</button>
</form>
<script>
// The promo code is inserted into this JS string literal by the server. The
// value is "sanitised" by stripping < and > only -- which does nothing here.
var promo = '"""

PAGE_POST = """';
document.getElementById('promo').innerText = promo;
</script>
<hr><small>Trouble with a code? <a href="/report-help">Report a checkout link to our staff.</a></small>
</body></html>"""


def _strip_angles(value: str) -> str:
    """The naive (and useless-in-JS-context) filter: remove HTML angle brackets."""
    return value.replace("<", "").replace(">", "")


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    # Absent promo -> empty string, so the inline script is always well-formed.
    raw = request.args.get("promo", "")
    filtered = _strip_angles(raw)
    # Raw string concatenation into the JS string literal -- no JS-string
    # encoding, no HTML escaping beyond the angle strip. This is the sink.
    body = PAGE_PRE + filtered + PAGE_POST
    return Response(body, mimetype="text/html")


@app.get("/api/whoami")
def whoami() -> Response:
    """Identity endpoint. To a request that already carries the admin `session`
    cookie it discloses the admin token; to everyone else it just says "guest".
    Same-origin JavaScript running in the admin's browser can therefore read the
    token via a credentialed fetch -- which is exactly what the XSS payload does."""
    session = request.cookies.get("session", "")
    if ADMIN_SESSION and hmac.compare_digest(session, ADMIN_SESSION):
        return Response(json.dumps({"user": "admin", "token": ADMIN_SESSION}),
                        mimetype="application/json")
    return Response(json.dumps({"user": "guest"}), mimetype="application/json")


@app.get("/report-help")
def report_help() -> Response:
    return Response(
        "<!doctype html><h1>Report a checkout link</h1>"
        "<p>POST /report with form field <code>url</code> (a path on this site). "
        "Our staff reviews reported checkout links automatically.</p>",
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
    # NON-HttpOnly on purpose: a credentialed same-origin fetch from the injected
    # script must send it. HttpOnly would not stop this particular exfil (the
    # fetch reads /api/whoami, not document.cookie), which is precisely why
    # contextual output encoding -- not just the cookie flag -- is the real fix.
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
    # The payload may exfiltrate the whole "session=<value>" cookie string or the
    # bare token; accept either the value or the name=value form.
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
