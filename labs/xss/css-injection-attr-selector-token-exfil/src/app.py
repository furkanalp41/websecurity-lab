# SPDX-License-Identifier: MIT
"""Stylr — a newsletter-preview tool. A contributor supplies a stylesheet
(POST /styles); staff preview the newsletter on GET /preview, which renders the
supplied stylesheet via <link rel="stylesheet" href="/styles.css"> alongside a
hidden-in-practice CSRF token held in an <input value="..."> (an ATTRIBUTE).

The preview page's CSP is strict on scripts (`script-src 'none'`) — no inline or
external JavaScript runs at all — but it renders an attacker-controlled stylesheet.
So the ONLY exfiltration primitive is CSS: attribute selectors
(`input[name="csrf"][value^="a0"] { background: url(...) }`) fire a background-image
request only when the token starts with a given prefix, leaking it one character at
a time to the collector. Because CSS attribute selectors read only ATTRIBUTE values
(never text nodes) and no endpoint returns the token, CSS is genuinely the only way
out.

The leaked token then authorises POST /admin/action; once that succeeds, POST
/solve returns the flag. /preview is admin-only, so an attacker can never read the
token directly — only the admin bot renders it, and only CSS carries it out.
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
ADMIN_CSRF = os.environ.get("ADMIN_CSRF", "")  # the short (8-hex) token to leak
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_CSS = 200000

app = Flask(__name__)
_state = {"css": "/* no stylesheet supplied yet */", "action_done": False}


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
        "<!doctype html><html><head><title>Stylr</title></head><body>"
        "<h1>Stylr — newsletter preview</h1>"
        "<p>Submit a stylesheet: <code>POST /styles {\"css\":\"...\"}</code>. "
        "Staff preview it at <code>/preview</code> (staff only). The preview page "
        "carries a CSRF token used by <code>POST /admin/action</code>.</p></body></html>",
        mimetype="text/html",
    )


@app.post("/styles")
def set_styles() -> Response:
    """Public: host a stylesheet for the newsletter preview (attacker-controlled)."""
    css = ""
    if request.is_json:
        css = str((request.get_json(silent=True) or {}).get("css", ""))
    if not css:
        css = request.form.get("css", "")
    if len(css) > MAX_CSS:
        return Response(json.dumps({"ok": False, "error": "stylesheet too large"}),
                        mimetype="application/json", status=413)
    _state["css"] = css
    return Response(json.dumps({"ok": True, "bytes": len(css)}), mimetype="application/json")


@app.get("/styles.css")
def get_styles() -> Response:
    resp = Response(_state["css"], mimetype="text/css")
    # Re-fetched fresh on every preview load so a new per-character stylesheet
    # applies each round (no stale cached CSS).
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@app.get("/preview")
def preview() -> Response:
    """Staff-only. Renders the supplied stylesheet + the CSRF token in an <input>
    value attribute, under a script-blocking CSP."""
    if not _is_admin():
        return Response("forbidden — staff only", status=403, mimetype="text/plain")
    page = (
        "<!doctype html><html><head><title>Preview</title>"
        "<link rel=\"stylesheet\" href=\"/styles.css\">"
        "</head><body>"
        "<h1>Newsletter preview</h1>"
        # The CSRF token lives in an ATTRIBUTE of a rendered input (so a CSS
        # background on it actually paints). A CSS attribute selector can read it;
        # script cannot (script-src 'none'), and no endpoint returns it.
        "<input type=\"text\" name=\"csrf\" value=\"%s\" readonly>"
        "<p>Preview rendered.</p></body></html>"
    ) % html.escape(ADMIN_CSRF)
    return Response(page, mimetype="text/html")


@app.after_request
def set_csp(resp: Response) -> Response:
    # Strict on scripts (no inline/external JS anywhere) but renders an
    # attacker-controlled stylesheet + allows img-src for the background-image
    # callbacks -> CSS attribute selectors are the ONLY exfil primitive. Set
    # globally (incl. the /preview 403) so the policy is observable.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; "
        "img-src *; font-src *; base-uri 'none'; object-src 'none'"
    )
    return resp


@app.post("/admin/action")
def admin_action() -> Response:
    """The state change the CSRF token guards. Authorised by the token itself —
    which is exactly why leaking it (via CSS) completes the attack."""
    body = request.get_json(silent=True) or {}
    token = str(body.get("csrf", "")) or request.form.get("csrf", "")
    if ADMIN_CSRF and hmac.compare_digest(token, ADMIN_CSRF):
        _state["action_done"] = True
        return Response(json.dumps({"ok": True, "action": "performed"}), mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "invalid or missing CSRF token"}),
                    mimetype="application/json", status=403)


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


@app.get("/internal/bot-login")
def bot_login() -> Response:
    if not _from_backend():
        return Response("forbidden", status=403, mimetype="text/plain")
    if not BOT_KEY or request.args.get("k", "") != BOT_KEY:
        return Response("forbidden", status=403, mimetype="text/plain")
    resp = Response("logged in", mimetype="text/plain")
    resp.set_cookie("session", ADMIN_SESSION, httponly=True, samesite="Lax")
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
