# SPDX-License-Identifier: MIT
"""Avatar Yard — a tiny profile app that accepts **SVG avatars**.

POST /avatar takes a multipart upload and "validates" it two ways: the part's
Content-Type must be `image/svg+xml` AND the bytes must start with `<svg`. That
is the whole check — it never strips `<script>`/event handlers. The raw SVG is
stored in-process under a uuid and served back verbatim:

  * GET /avatars/<uuid>.svg returns the bytes with Content-Type image/svg+xml —
    i.e. as a real **SVG document**, so any script inside runs when the file is
    loaded *as a document*; and
  * GET /u/<uuid> (the public profile page) embeds that avatar with
    `<object data="/avatars/<uuid>.svg" type="image/svg+xml">` — NOT `<img>`.
    An `<object>` loads the SVG as a document in the *app's own origin*, so its
    `<script>` executes with the app's cookies in scope. (`<img src>` would
    rasterise the SVG and never run its scripts — that is the safe path.)

The victim is the shared xss-verifier headless-Chromium admin bot. It logs in
via GET /internal/bot-login?k=<BOT_KEY> (the app Set-Cookies the admin `session`
cookie), polls GET /internal/queue for paths submitted through the public
POST /report form, and visits each one. A malicious SVG avatar embedded on a
reported /u/<uuid> profile therefore runs in the admin's browser; a same-origin
`fetch('/admin/token')` from inside it carries the admin cookie and returns the
admin session, which the payload beacons to the in-lab collector. Read it back
through GET /oob/received and submit it to POST /solve for the flag.
"""
import collections
import hmac
import ipaddress
import json
import os
import urllib.request
import uuid

from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
# /internal/* endpoints are firewalled to the internal backend subnet: the admin
# bot lives there, but the public (edge/published-port) side does NOT, so a lab
# visitor cannot request the admin cookie or read the bot queue directly. This is
# what forces the intended stored-XSS path instead of a trivial cookie fetch.
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_QUEUE = 64
MAX_SVG = 256 * 1024  # a sane cap on a stored avatar; the exploit SVG is tiny

app = Flask(__name__)
# Bound the multipart body so an oversized upload cannot exhaust the container.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024


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


# Single-worker in-process state: pending bot paths + the stored SVG avatars.
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)
_avatars: dict[str, bytes] = {}


HOME = """<!doctype html><html><head><title>Avatar Yard</title></head><body>
<h1>Avatar Yard</h1>
<p>Upload an <strong>SVG avatar</strong> and share your profile.</p>
<form action="/avatar" method="post" enctype="multipart/form-data">
  <input type="file" name="avatar" accept="image/svg+xml">
  <button type="submit">Upload avatar</button>
</form>
<p>Uploads return a profile URL like <code>/u/&lt;id&gt;</code>. Think a profile
is misbehaving? <a href="/report-help">Report it to our staff.</a></p>
</body></html>"""


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    return Response(HOME, mimetype="text/html")


@app.post("/avatar")
def avatar_upload() -> Response:
    """Public: accept an SVG avatar. VALIDATION FLAW — it checks only that the
    multipart part is declared `image/svg+xml` and that the bytes begin with
    `<svg`; it never strips `<script>` or event handlers, so a scripted SVG is
    stored verbatim and later served as an executable document."""
    f = request.files.get("avatar")
    if f is None:
        return Response(json.dumps({"ok": False, "error": "file field 'avatar' required"}),
                        mimetype="application/json", status=400)
    # Check 1: the client-declared MIME type of the uploaded part.
    if f.mimetype != "image/svg+xml":
        return Response(json.dumps({"ok": False, "error": "avatar must be image/svg+xml"}),
                        mimetype="application/json", status=415)
    raw = f.read(MAX_SVG + 1)
    if len(raw) > MAX_SVG:
        return Response(json.dumps({"ok": False, "error": "avatar too large"}),
                        mimetype="application/json", status=413)
    # Check 2: a magic-prefix sniff. Note what is MISSING — no sanitisation of
    # the SVG body, so <script>/onload survive intact.
    if not raw.lstrip()[:4].lower() == b"<svg":
        return Response(json.dumps({"ok": False, "error": "not an SVG (must start with <svg)"}),
                        mimetype="application/json", status=422)
    uid = uuid.uuid4().hex
    _avatars[uid] = raw
    return Response(json.dumps({"ok": True, "uuid": uid, "profile": "/u/" + uid}),
                    mimetype="application/json")


@app.get("/avatars/<avatar_id>.svg")
def avatar_serve(avatar_id: str) -> Response:
    """Serve the stored avatar as a real SVG DOCUMENT (image/svg+xml). Because
    this is a document, its scripts run when it is loaded via <object>/<iframe>
    or navigated to directly. (Default string converter — the store keys are
    uuid4().hex, i.e. 32 hex chars with no dashes, which the <uuid> converter
    would NOT match.)"""
    raw = _avatars.get(avatar_id)
    if raw is None:
        return Response("not found", status=404, mimetype="text/plain")
    return Response(raw, mimetype="image/svg+xml")


@app.get("/u/<avatar_id>")
def profile(avatar_id: str) -> Response:
    """Public profile page. VULNERABILITY: the avatar is embedded as a DOCUMENT
    via <object type="image/svg+xml"> (not <img>), so a scripted SVG executes in
    this origin when the page is loaded."""
    if avatar_id not in _avatars:
        return Response("no such profile", status=404, mimetype="text/plain")
    # `avatar_id` is a route-matched key that exists in the store (uuid4 hex), so
    # it is safe to interpolate into the embed.
    page = (
        "<!doctype html><html><head><title>Profile</title></head><body>"
        "<h1>Profile " + avatar_id + "</h1>"
        "<p>Member avatar:</p>"
        "<object data=\"/avatars/" + avatar_id + ".svg\" type=\"image/svg+xml\" "
        "width=\"200\" height=\"200\"></object>"
        "<hr><small>Found a bug? <a href=\"/report-help\">Report a page to our staff.</a></small>"
        "</body></html>"
    )
    return Response(page, mimetype="text/html")


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


@app.get("/admin/token")
def admin_token() -> Response:
    """Admin-only: returns the current admin session token as text/plain. Gated
    to the admin `session` cookie, so only the bot's browser can read it — but a
    same-origin `fetch()` from a script running in this origin carries that
    cookie automatically (even if it were HttpOnly), which is exactly what the
    scripted-SVG avatar abuses."""
    if not _is_admin():
        return Response("forbidden — admin only", status=403, mimetype="text/plain")
    return Response(ADMIN_SESSION, mimetype="text/plain")


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
    # NON-HttpOnly to match the reflected/stored labs' cookie model. The theft
    # here does not even depend on it: the payload reads the admin token via a
    # same-origin fetch, which sends the cookie regardless of HttpOnly.
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
