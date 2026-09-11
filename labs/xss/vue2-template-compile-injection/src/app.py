# SPDX-License-Identifier: MIT
"""WidgetHub — a dashboard that lets customers supply a custom "widget template"
which the admin's dashboard compiles at runtime with **Vue.compile()** (Vue 2.7),
a client-side template-injection (CSTI) sink.

POST /widget stores a raw template string. GET /admin/dashboard (admin-only)
embeds the latest stored template in a hidden <div id="w"> (HTML-escaped, so it
is inert) and does, in the page:

    var tpl = document.getElementById('w').textContent;   // entities decoded back
    var compiled = Vue.compile(tpl);
    new Vue({ el: '#app', render: compiled.render, staticRenderFns: compiled.staticRenderFns });

Vue.compile turns the attacker's template into a render function whose {{ }}
expressions run in the component's scope (Vue 2 compiles to `with(this){...}`, so
`constructor.constructor` reaches the Function constructor). Compiling untrusted
templates is remote template injection.

The victim is the shared xss-verifier admin bot: it logs in
(GET /internal/bot-login?k=<BOT_KEY> — non-HttpOnly `session` cookie) and loads
its fixed URL GET /admin/dashboard every couple of seconds. A stored template
expression therefore runs in the admin's browser; a same-origin fetch('/me')
returns the admin token, which the payload beacons to the in-lab collector. Read
it back through GET /oob/received and POST /solve for the flag.
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
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
# /internal/* + /admin/* are firewalled to the admin cookie / backend subnet, so a
# public visitor cannot mint the admin cookie or read /me directly — the CSTI
# must fire in the bot to reach the token.
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_WIDGETS = 32

app = Flask(__name__)

# Single-worker, in-process store of submitted widget templates (newest last).
_widgets: collections.deque = collections.deque(maxlen=MAX_WIDGETS)


def _from_backend() -> bool:
    try:
        peer = ipaddress.ip_address(request.remote_addr or "")
        return peer in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


def _is_admin() -> bool:
    return bool(ADMIN_SESSION) and hmac.compare_digest(
        request.cookies.get("session", ""), ADMIN_SESSION
    )


HOME = (
    "<!doctype html><html><head><title>WidgetHub</title></head><body>"
    "<h1>WidgetHub</h1>"
    "<p>Build a custom dashboard widget. Submit a Vue template and our staff "
    "previews it on the admin dashboard.</p>"
    "<p>Post a widget: <code>POST /widget</code> with JSON "
    "<code>{\"template\": \"&lt;span&gt;hello&lt;/span&gt;\"}</code> or a form "
    "field <code>template</code>.</p>"
    "</body></html>"
)

# The admin dashboard. VULNERABILITY: the latest stored template is embedded in a
# a hidden <div> and handed to Vue.compile() at runtime. html.escape() renders the
# div content as inert text (no HTML/attribute injection), but element.textContent
# DECODES the entities, so the raw attacker template — and its {{ }} expressions —
# reach the compiler and execute in the Vue scope. (Reading a <script> via innerHTML
# would NOT decode entities — a <div> read via textContent does.)
DASH_HEAD = (
    "<!doctype html><html><head><meta charset=\"utf-8\">"
    "<title>WidgetHub — Admin Dashboard</title>"
    "<script src=\"/vendor/lib.min.js\"></script></head><body>"
    "<h1>Admin Dashboard</h1><p>Previewing the latest customer widget:</p>"
    "<div id=\"app\"></div>"
    "<div id=\"w\" style=\"display:none\">"
)
DASH_TAIL = (
    "</div>"
    "<script>"
    "(function(){"
    "  var tpl = document.getElementById('w').textContent;"
    "  try {"
    "    var compiled = Vue.compile(tpl);"
    "    new Vue({ el: '#app', render: compiled.render, staticRenderFns: compiled.staticRenderFns });"
    "  } catch (e) { document.getElementById('app').textContent = 'widget failed to render'; }"
    "})();"
    "</script></body></html>"
)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    return Response(HOME, mimetype="text/html")


@app.post("/widget")
def create_widget() -> Response:
    """Public: store a widget template string. Accepts form or JSON."""
    template = ""
    if request.is_json:
        template = str((request.get_json(silent=True) or {}).get("template", ""))
    if not template:
        template = request.form.get("template", "")
    template = template.strip()
    if not template:
        return Response(json.dumps({"ok": False, "error": "template required"}),
                        mimetype="application/json", status=400)
    _widgets.append(template)
    return Response(json.dumps({"ok": True, "count": len(_widgets)}),
                    mimetype="application/json")


@app.get("/admin/dashboard")
def admin_dashboard() -> Response:
    """Admin-only: runtime-compile the latest widget template with Vue.compile."""
    if not _is_admin():
        return Response("forbidden — admin only", status=403, mimetype="text/plain")
    template = _widgets[-1] if _widgets else "<span>No widgets yet.</span>"
    page = DASH_HEAD + html.escape(template) + DASH_TAIL
    return Response(page, mimetype="text/html")


@app.get("/me")
def me() -> Response:
    """Admin-only identity endpoint: discloses the admin token to a request that
    carries the admin cookie. A same-origin fetch from a script running in the
    admin's browser sends that cookie automatically — which the CSTI abuses."""
    if not _is_admin():
        return Response("forbidden — admin only", status=403, mimetype="text/plain")
    return Response(json.dumps({"user": "admin", "token": ADMIN_SESSION}),
                    mimetype="application/json")


@app.get("/vendor/lib.min.js")
def vendor_lib() -> Response:
    """Serve the vendored Vue 2.7.16 FULL build (includes the runtime compiler
    that Vue.compile needs). Intentionally an EOL major — runtime compilation of
    user templates is the vulnerability; it is not 'upgraded'."""
    try:
        with open(os.path.join(os.path.dirname(__file__), "lib.min.js"), encoding="utf-8") as fh:
            return Response(fh.read(), mimetype="application/javascript")
    except OSError:
        return Response("// unavailable", mimetype="application/javascript", status=500)


@app.get("/internal/bot-login")
def bot_login() -> Response:
    """Bot-only: mint the admin session cookie. Backend-firewalled + BOT_KEY."""
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
    return Response(json.dumps({"ok": False, "error": "that is not the admin token"}),
                    mimetype="application/json", status=403)
