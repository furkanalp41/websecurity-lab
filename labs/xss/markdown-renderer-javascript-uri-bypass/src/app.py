# SPDX-License-Identifier: MIT
"""WikiLite — a wiki whose markdown link renderer "sanitises" hrefs by stripping
`javascript:` with a single-pass, case-insensitive regex. That filter is trivially
bypassed: `java&#9;script:` — a literal TAB inside the scheme — does not match the
regex, but the browser strips tab/newline/CR from URLs when it navigates, so the
href resolves back to `javascript:` and executes when the link is activated.

The admin bot (the shared xss-verifier headless Chromium, configured with
XSSBOT_CLICK_SELECTOR) reviews new pages and CLICKS the primary link in each, so a
bypassed `javascript:` link runs in the admin's browser and steals the non-HttpOnly
session cookie. Recover it via GET /oob/received and POST /solve.
"""
import collections
import hmac
import ipaddress
import json
import os
import re
import urllib.request

from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_PAGES = 32

app = Flask(__name__)
_pages: collections.deque = collections.deque(maxlen=MAX_PAGES)


def _from_backend() -> bool:
    try:
        return ipaddress.ip_address(request.remote_addr or "") in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


def _is_admin() -> bool:
    return bool(ADMIN_SESSION) and hmac.compare_digest(
        request.cookies.get("session", ""), ADMIN_SESSION
    )


# A minimal markdown link renderer with the DELIBERATELY FLAWED sanitiser: it
# removes the substring "javascript:" (case-insensitive) from the href in a single
# pass, then drops the RAW url into the href attribute. It does NOT strip control
# characters, so `java<TAB>script:` slips through — and the browser normalises the
# scheme (removing the tab) when the link is activated.
_LINK = re.compile(r"\[([^\]]+)\]\((.+)\)", re.S)


def _sanitise_href(url: str) -> str:
    url = re.sub(r"javascript:", "", url, flags=re.IGNORECASE)  # single pass, the flaw
    return url.replace('"', "&quot;")  # attribute-safe only against " breakout


def render_markdown(body: str) -> str:
    m = _LINK.search(body)
    if not m:
        return "<p>%s</p>" % html_escape(body)
    pre = html_escape(body[: m.start()])
    post = html_escape(body[m.end():])
    text = html_escape(m.group(1))
    href = _sanitise_href(m.group(2))
    return "<p>%s<a class=\"wiki-link\" href=\"%s\">%s</a>%s</p>" % (pre, href, text, post)


def html_escape(s: str) -> str:
    import html
    return html.escape(s)


HOME = (
    "<!doctype html><html><head><title>WikiLite</title></head><body>"
    "<h1>WikiLite</h1>"
    "<p>Draft a wiki page in markdown. Our staff reviews new pages "
    "(they open the primary link to check it).</p>"
    "<p><code>POST /pages</code> with JSON <code>{\"body\":\"[text](url)\"}</code> "
    "or a form field <code>body</code>.</p>"
    "</body></html>"
)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    return Response(HOME, mimetype="text/html")


@app.post("/pages")
def create_page() -> Response:
    body = ""
    if request.is_json:
        body = str((request.get_json(silent=True) or {}).get("body", ""))
    if not body:
        body = request.form.get("body", "")
    body = body.strip()
    if not body:
        return Response(json.dumps({"ok": False, "error": "body required"}),
                        mimetype="application/json", status=400)
    _pages.append(render_markdown(body))
    return Response(json.dumps({"ok": True, "count": len(_pages)}), mimetype="application/json")


@app.get("/admin/review")
def admin_review() -> Response:
    """Admin-only: renders the latest page. The bot clicks its primary link
    (XSSBOT_CLICK_SELECTOR=a.wiki-link)."""
    if not _is_admin():
        return Response("forbidden — admin only", status=403, mimetype="text/plain")
    latest = _pages[-1] if _pages else "<p>No pages yet.</p>"
    page = ("<!doctype html><html><head><title>Review</title></head><body>"
            "<h1>Page review</h1>%s</body></html>") % latest
    return Response(page, mimetype="text/html")


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
