# SPDX-License-Identifier: MIT
"""HelpDesk — a legacy help-centre page whose "scroll to section" feature passes
the URL fragment straight to the jQuery function, a DOM-based XSS.

On load the page runs:

    var t = decodeURIComponent(location.hash.slice(1));
    if (t) { $(t); }

The intent was `$("#some-section")` — select an element and (elsewhere) scroll to
it. But jQuery's `$()` is overloaded: when handed a string that *looks like HTML*
(starts with `<...>`), it does not SELECT, it CONSTRUCTS the described elements.
So a fragment like `<img src=x onerror=...>` builds a detached <img> whose broken
`src` fires `onerror` — attacker JavaScript, no injection into markup required.

This is worse on the vendored jQuery **3.4.1**: versions < 3.5 treat a broader
range of strings (including ones with leading whitespace) as HTML-to-construct,
so the selector-vs-HTML boundary is fuzzier and easier to cross. jQuery >= 3.5
tightened `htmlPrefilter`/`rquickExpr`, but the real fix is never passing
untrusted input to `$()` at all.

The admin bot (the shared xss-verifier headless Chromium) visits any path you
submit to POST /report while holding its non-HttpOnly `session` cookie, so a
payload that reads document.cookie and beacons it to the in-lab collector steals
the admin session. Recover it via GET /oob/received and POST /solve.
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
# /internal/* endpoints are firewalled to the internal backend subnet: the admin
# bot lives there, but the public (edge/published-port) side does NOT, so a lab
# visitor cannot request the admin cookie or read the bot queue directly. This is
# what forces the intended DOM-XSS path instead of a trivial cookie fetch.
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_QUEUE = 64

app = Flask(__name__)

# Single-worker, in-process queue of paths the admin bot has yet to visit.
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)

# The vulnerable help-centre page. It ships the vendored jQuery 3.4.1 and, on
# load, passes the URL fragment to $() to "scroll to a section" — the DOM sink.
# (source: location.hash, sink: the jQuery $() constructor.)
PAGE = """<!doctype html><html><head><title>HelpDesk</title>
<script src="/vendor/lib.min.js"></script></head><body>
<h1>HelpDesk — Knowledge Base</h1>
<nav><a href="#getting-started">Getting started</a> |
<a href="#billing">Billing</a> | <a href="#security">Security</a></nav>
<article>
  <h2 id="getting-started">Getting started</h2>
  <p>Welcome to HelpDesk. Deep-link to any section with a #fragment and the page
  scrolls straight to it.</p>
  <h2 id="billing">Billing</h2>
  <p>Manage invoices and payment methods from your account settings.</p>
  <h2 id="security">Security</h2>
  <p>Reset credentials and review sign-in activity here.</p>
</article>
<script>
// DELIBERATE DOM XSS: the "scroll to section" helper passes the URL fragment
// straight to jQuery's $() function. $() with an HTML-looking string CONSTRUCTS
// elements instead of selecting them, so a fragment such as
//   <img src=x onerror=...>
// builds an <img> whose onerror fires. A real app would select by id only, e.g.
// document.getElementById(t) or $(document).find('#' + cssEscape(t)) — never
// pass raw location.hash to $(). jQuery 3.4.1 (< 3.5) widens what counts as HTML.
(function () {
  var t = decodeURIComponent(location.hash.slice(1));
  if (t) { $(t); }
})();
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


@app.get("/vendor/lib.min.js")
def vendor_lib() -> Response:
    """Serve the vendored framework (jQuery 3.4.1) from disk. The main session
    places src/lib.min.js at build time; the deliberately end-of-life version IS
    the lesson (the pre-3.5 $() selector-to-HTML quirk), so it is not upgraded."""
    try:
        with open(os.path.join(os.path.dirname(__file__), "lib.min.js"), encoding="utf-8") as fh:
            return Response(fh.read(), mimetype="application/javascript")
    except OSError:
        return Response("// unavailable", mimetype="application/javascript", status=500)


@app.post("/report")
def report() -> Response:
    """Public: queue a path for the admin bot to review. Accepts form or JSON.
    The path may carry a #fragment — the bot visits it in a real browser, so the
    fragment reaches location.hash (it never touches the server)."""
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
