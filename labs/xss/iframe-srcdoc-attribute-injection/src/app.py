# SPDX-License-Identifier: MIT
"""NoteWall — a tiny notes app whose rich-post renderer sanitizes user HTML with
Bleach 6, but with a **misconfigured allowlist** that permits `<iframe>` carrying
a `srcdoc` attribute (stored XSS via iframe srcdoc).

Anyone can POST a note to /posts; the body is passed through `bleach.clean` and
the sanitized HTML is kept in an in-process list. The admin bot (the shared
xss-verifier headless Chromium) holds a non-HttpOnly `session` cookie and loads a
fixed admin page — GET /admin/feed — every couple of seconds, which renders every
stored note as raw HTML.

Bleach vets tag/attribute *names*, not attribute *value semantics*. It has no way
to know that an `<iframe srcdoc="...">` value is itself an HTML document, parsed
in an inherited-origin `about:srcdoc` browsing context. So the iframe and its
srcdoc survive sanitization (the value merely HTML-escaped); when the admin's
browser renders the feed it decodes that value and runs any `<script>` inside it
with the **parent origin's** cookies in scope — i.e. the admin's non-HttpOnly
session. Exfiltrate it to the in-lab collector; read it back through
GET /oob/received; submit it to POST /solve for the flag.
"""
import collections
import hmac
import ipaddress
import json
import os
import urllib.request

import bleach
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
# /internal/* endpoints are firewalled to the internal backend subnet: the admin
# bot lives there, but the public (edge/published-port) side does NOT, so a lab
# visitor cannot request the admin cookie directly. This is what forces the
# intended stored-XSS path instead of a trivial cookie fetch.
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_POSTS = 64

app = Flask(__name__)


def _from_backend() -> bool:
    try:
        peer = ipaddress.ip_address(request.remote_addr or "")
        return peer in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


# Single-worker, in-process store of sanitized note HTML (newest last).
_posts: collections.deque = collections.deque(maxlen=MAX_POSTS)

# DELIBERATE VULNERABILITY: the rich-post sanitizer's allowlist permits <iframe>
# together with a `srcdoc` attribute. Bleach only vets tag/attribute *names*; it
# cannot know that srcdoc's *value* is an HTML document parsed in an
# inherited-origin about:srcdoc context. A real app would never allow-list
# <iframe srcdoc> on user content; this lab mimics a team that added it "so notes
# can embed a small rendered preview" — the canonical allowlist-semantics footgun.
ALLOWED_TAGS = [
    "p", "br", "b", "i", "em", "strong", "a", "ul", "ol", "li",
    "code", "pre", "blockquote", "h1", "h2", "h3", "span", "iframe",
]
ALLOWED_ATTRS = {
    "a": ["href", "title"],
    "span": ["class"],
    # The misconfig: `srcdoc` (plus width/height) is allowed on <iframe>.
    "iframe": ["srcdoc", "width", "height"],
}


def sanitize(body: str) -> str:
    """Allowlist-sanitize a note body. strip=True drops disallowed tags, but the
    allowlist above keeps <iframe srcdoc> — Bleach escapes the srcdoc value for
    HTML output yet leaves the attribute in place."""
    return bleach.clean(body, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)


HOME = (
    "<!doctype html><html><head><title>NoteWall</title></head><body>"
    "<h1>NoteWall</h1>"
    "<p>A place for rich notes. Formatting is sanitized on the server before it is"
    " stored.</p>"
    "<p>Post a note: <code>POST /posts</code> with JSON <code>{\"body\": \"...\"}</code>"
    " or a form field <code>body</code>. Staff review new notes on the internal"
    " admin feed.</p>"
    "</body></html>"
)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    return Response(HOME, mimetype="text/html")


@app.post("/posts")
def create_post() -> Response:
    """Public: store a rich note. Accepts form or JSON. The body is sanitized with
    the (misconfigured) Bleach allowlist and the result kept in-process."""
    body = ""
    if request.is_json:
        body = str((request.get_json(silent=True) or {}).get("body", ""))
    if not body:
        body = request.form.get("body", "")
    body = body.strip()
    if not body:
        return Response(json.dumps({"ok": False, "error": "body required"}),
                        mimetype="application/json", status=400)
    clean = sanitize(body)
    _posts.append(clean)
    # Echo the stored (sanitized) HTML so an attacker can confirm the allowlist
    # kept their <iframe srcdoc> rather than stripping it.
    return Response(json.dumps({"ok": True, "stored": clean, "count": len(_posts)}),
                    mimetype="application/json")


@app.get("/admin/feed")
def admin_feed() -> Response:
    """Admin-only feed. VULNERABILITY: every stored note is rendered as RAW HTML.
    Because the sanitizer let <iframe srcdoc> through, the admin's browser parses
    the srcdoc as a document in an inherited-origin context and runs its script.
    Gated to the admin session so only the bot (which holds it) can load it."""
    if not (ADMIN_SESSION and hmac.compare_digest(request.cookies.get("session", ""), ADMIN_SESSION)):
        return Response("forbidden — admin only", status=403, mimetype="text/plain")
    parts = [
        "<!doctype html><html><head><title>NoteWall — Admin Feed</title></head>"
        "<body><h1>Admin Feed</h1><p>Newest notes awaiting review.</p><hr>"
    ]
    for html in _posts:
        parts.append("<article>%s</article>" % html)
    parts.append("</body></html>")
    return Response("".join(parts), mimetype="text/html")


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
    if ADMIN_SESSION and hmac.compare_digest(submitted, ADMIN_SESSION):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(json.dumps({"ok": True, "flag": flag}), mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "that is not the admin session"}),
                    mimetype="application/json", status=403)
