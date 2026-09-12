# SPDX-License-Identifier: MIT
"""Profilr — a profile app with the classic **self-XSS shrug**: your bio is
HTML-escaped when anyone ELSE views your profile (`GET /u/<name>`), but rendered
RAW when YOU view your own (`GET /profile`). On its own that is "just self-XSS" —
you can only run script in your own session, which is pointless.

Two things turn it into a real account takeover:
  1. The bio-update endpoint is `GET /profile/update?bio=...` (state change via
     GET), session-gated but with **no CSRF token** ("it's only self-XSS anyway").
  2. So an attacker page can CSRF the admin's bio — and because it is a top-level
     GET navigation, the admin's `SameSite=Lax` session cookie IS sent. After the
     update redirects the admin to their own `/profile`, the planted self-XSS runs
     in the admin's session and steals the (non-HttpOnly) cookie.

The admin bot visits any URL queued via POST /report (here, the attacker page).
"""
import collections
import hmac
import html
import ipaddress
import json
import os
import urllib.parse
import urllib.request

from flask import Flask, Response, redirect, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_QUEUE = 64

app = Flask(__name__)
_queue: collections.deque = collections.deque(maxlen=MAX_QUEUE)
# Single admin user; single gunicorn worker keeps this bio consistent.
_bio = {"admin": "Hi, I'm the site administrator."}


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
        "<!doctype html><html><head><title>Profilr</title></head><body>"
        "<h1>Profilr</h1><p>Edit your bio at "
        "<code>GET /profile/update?bio=...</code>; view your own at "
        "<code>/profile</code>. Others see it at <code>/u/&lt;name&gt;</code>. "
        "Found a bad page? <code>POST /report {\"url\":\"...\"}</code>.</p></body></html>",
        mimetype="text/html",
    )


@app.get("/profile")
def profile() -> Response:
    """Your OWN profile — bio rendered RAW (the self-XSS footgun)."""
    if not _is_admin():
        return Response("forbidden — log in to see your own profile", status=403, mimetype="text/plain")
    bio = _bio.get("admin", "")
    page = ("<!doctype html><html><head><title>Your profile</title></head><body>"
            "<h1>Your profile (admin)</h1>"
            "<div class=\"bio\">%s</div>"  # RAW — self-XSS
            "</body></html>") % bio
    return Response(page, mimetype="text/html")


@app.get("/u/<name>")
def public_profile(name: str) -> Response:
    """Public view of a profile — bio HTML-ESCAPED (safe for other viewers)."""
    bio = _bio.get(name)
    if bio is None:
        return Response("no such user", status=404, mimetype="text/plain")
    page = ("<!doctype html><html><head><title>%s</title></head><body>"
            "<h1>%s</h1><div class=\"bio\">%s</div>"  # ESCAPED
            "</body></html>") % (html.escape(name), html.escape(name), html.escape(bio))
    return Response(page, mimetype="text/html")


@app.get("/profile/update")
def profile_update() -> Response:
    """DELIBERATE FLAW: state change via GET, session-gated but with NO CSRF token.
    A cross-site top-level GET navigation carries the admin's SameSite=Lax cookie,
    so an attacker page can set the admin's bio. Redirects to the owner view where
    the raw bio (self-XSS) runs."""
    if not _is_admin():
        return Response("forbidden — log in first", status=403, mimetype="text/plain")
    _bio["admin"] = request.args.get("bio", "")
    return redirect("/profile", code=302)


@app.post("/report")
def report() -> Response:
    """Report a page for staff review. Accepts a full URL (the admin bot visits it)."""
    url = ""
    if request.is_json:
        url = str((request.get_json(silent=True) or {}).get("url", ""))
    if not url:
        url = request.form.get("url", "")
    url = url.strip()
    if not url:
        return Response(json.dumps({"ok": False, "error": "url required"}),
                        mimetype="application/json", status=400)
    # Report EXTERNAL pages only: reject URLs pointing back at this app, so the
    # payload must be delivered cross-site (which is what exercises the
    # SameSite=Lax cross-site-GET-CSRF lesson) rather than by queuing the app's
    # own /profile/update directly.
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host in ("app", "localhost", "127.0.0.1", "0.0.0.0", ""):
        return Response(json.dumps({"ok": False, "error": "report an external page, not one on this site"}),
                        mimetype="application/json", status=400)
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
