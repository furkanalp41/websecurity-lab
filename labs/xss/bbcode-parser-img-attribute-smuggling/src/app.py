# SPDX-License-Identifier: MIT
"""Vault Forum — a vintage message board whose BBCode renderer turns
``[img]URL[/img]`` into ``<img src="URL">`` **without HTML-attribute-encoding
the URL**. Everything else in a post body is safely escaped, but the captured
``[img]`` URL is inserted RAW into the ``src`` attribute, so a URL containing a
double quote breaks out of ``src`` and opens new attributes (e.g. ``onerror``).
This is stored XSS: the payload persists in a topic and later fires in a
different, higher-privileged browser.

The victim is an admin bot (the shared xss-verifier headless Chromium) that:
  * logs in via GET /internal/bot-login?k=<BOT_KEY> — the app Set-Cookies the
    admin `session` cookie (non-HttpOnly, so document.cookie can read it — that
    is the misconfiguration the cookie-theft turns on), then
  * loads the fixed admin board GET /admin/topics every loop, which renders
    every stored topic's title + BBCode-rendered body.

A stored [img] payload whose URL smuggles an onerror handler therefore runs in
the admin's browser with the admin cookie in scope. Exfiltrate it to the in-lab
collector; read it back through GET /oob/received (the collector sits on the
egress-dropped backend network); submit it to POST /solve for the flag.
"""
import html
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
# /internal/* endpoints are firewalled to the internal backend subnet: the admin
# bot lives there, but the public (edge/published-port) side does NOT, so a lab
# visitor cannot request the admin cookie directly. This is what forces the
# intended stored-XSS path instead of a trivial cookie fetch.
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")
MAX_TOPICS = 64

app = Flask(__name__)


def _from_backend() -> bool:
    try:
        peer = ipaddress.ip_address(request.remote_addr or "")
        return peer in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


# Single-worker, in-process store of posted topics ({"title", "html"}).
_topics: list = []


# DELIBERATE VULNERABILITY: a hand-rolled BBCode renderer. Every part of the
# body is HTML-escaped EXCEPT the URL captured inside [img]...[/img], which is
# concatenated RAW into the src attribute. Because the URL is not
# HTML-attribute-encoded, a `"` in it terminates the src value early and lets an
# attacker append arbitrary attributes such as onerror. A correct renderer would
# html.escape() the URL too (turning `"` into `&quot;`), keeping it inside src.
IMG_RE = re.compile(r"\[img\](.*?)\[/img\]", re.I | re.S)


def render_bbcode(body: str) -> str:
    """Render post BBCode to HTML.

    The text between/around [img] tags is html.escape()d (safe). For each
    [img]URL[/img] the captured URL is emitted RAW inside src="..." — the taught
    flaw: the only injection vector in a rendered post is the [img] URL.
    """
    out = []
    pos = 0
    for m in IMG_RE.finditer(body):
        out.append(html.escape(body[pos:m.start()]))
        # RAW, unescaped captured URL straight into the attribute value.
        out.append('<img src="' + m.group(1) + '">')
        pos = m.end()
    out.append(html.escape(body[pos:]))
    return "".join(out)


HOME_PAGE = (
    "<!doctype html><html><head><meta charset=\"utf-8\">"
    "<title>Vault Forum</title></head><body>"
    "<h1>Vault Forum</h1>"
    "<p>A cosy corner of the old web. Post a topic and our staff will review it "
    "on the moderation board.</p>"
    "<form action=\"/topics\" method=\"post\">"
    "  <p><input name=\"title\" placeholder=\"topic title\"></p>"
    "  <p><textarea name=\"body\" placeholder=\"body — BBCode allowed, e.g. "
    "[img]https://example/cat.png[/img]\"></textarea></p>"
    "  <button type=\"submit\">Post topic</button>"
    "</form>"
    "<hr><small>BBCode: <code>[img]URL[/img]</code> embeds a picture. New topics "
    "are queued for staff review on the admin board.</small>"
    "</body></html>"
)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def home() -> Response:
    return Response(HOME_PAGE, mimetype="text/html")


@app.post("/topics")
def create_topic() -> Response:
    """Public: post a forum topic. Accepts form or JSON {title, body}. The body
    is rendered through the BBCode renderer and stored for the admin board."""
    title = ""
    body = ""
    if request.is_json:
        data = request.get_json(silent=True) or {}
        title = str(data.get("title", ""))
        body = str(data.get("body", ""))
    if not title:
        title = request.form.get("title", "")
    if not body:
        body = request.form.get("body", "")
    title = title.strip()
    body = body.strip()
    if not body:
        return Response(json.dumps({"ok": False, "error": "body required"}),
                        mimetype="application/json", status=400)
    if not title:
        title = "(untitled)"
    if len(_topics) >= MAX_TOPICS:
        _topics.pop(0)
    _topics.append({"title": title, "html": render_bbcode(body)})
    return Response(json.dumps({"ok": True, "posted": title}),
                    mimetype="application/json")


@app.get("/admin/topics")
def admin_topics() -> Response:
    """Admin-only board: renders every stored topic's title + rendered body.

    Gated by the admin `session` cookie (constant-time compare). Only the admin
    bot, which minted the cookie via /internal/bot-login, can load this — which
    is why a stored payload must wait for the bot to render it here."""
    if not hmac.compare_digest(request.cookies.get("session", ""), ADMIN_SESSION):
        return Response("forbidden", status=403, mimetype="text/plain")
    articles = []
    for t in _topics:
        # The title is escaped (not a vector); the body html is already rendered
        # by render_bbcode, where the [img] URL was inserted raw — the sink.
        articles.append(
            "<article><h2>%s</h2><div class=\"post\">%s</div></article>"
            % (html.escape(t["title"]), t["html"])
        )
    page = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>Admin — Topic Moderation</title></head><body>"
        "<h1>Vault Forum — Admin Topic Board</h1>"
        "<p>All topics posted to the forum, oldest first.</p>"
        + ("".join(articles) if articles else "<p>No topics yet.</p>")
        + "</body></html>"
    )
    return Response(page, mimetype="text/html")


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
    # here would defeat the exfiltration and is the primary defence (see SOLUTION).
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
