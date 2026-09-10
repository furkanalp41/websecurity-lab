# SPDX-License-Identifier: MIT
"""The Bugle — a tiny Django blog with a stored XSS in comment moderation.

Anyone can POST a comment (it lands unapproved). The admin bot polls the
moderation page GET /admin/moderate every few seconds — and that template renders
each pending comment body with Django's `|safe` filter, disabling autoescaping.
Django autoescapes by default; a developer who reaches for `|safe` "to allow
basic formatting" reintroduces stored XSS. The bot loads the page with its
non-HttpOnly `session` cookie, so a payload in a comment runs in the admin's
browser and can steal that cookie.
"""
import hmac
import ipaddress
import json
import os
import urllib.request

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import Comment

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "")
BOT_KEY = os.environ.get("BOT_KEY", "")
OOB_HOST = os.environ.get("OOB_HOST", "collector")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))
BACKEND_CIDR = os.environ.get("BACKEND_CIDR", "172.31.240.0/24")


def _from_backend(request) -> bool:
    try:
        peer = ipaddress.ip_address(request.META.get("REMOTE_ADDR", ""))
        return peer in ipaddress.ip_network(BACKEND_CIDR)
    except ValueError:
        return False


@require_GET
def health(request):
    return HttpResponse("ok", content_type="text/plain")


@require_GET
def index(request):
    approved = Comment.objects.filter(approved=True)[:20]
    return render(request, "index.html", {"comments": approved})


@csrf_exempt
@require_POST
def post_comment(request):
    """Public: anyone may leave a comment. It is stored unapproved, awaiting
    moderation. Body is stored verbatim (the stored-XSS source)."""
    body = ""
    author = "anon"
    if request.content_type == "application/json":
        data = json.loads(request.body or b"{}")
        body = str(data.get("body", ""))
        author = str(data.get("author", "anon"))[:80]
    else:
        body = request.POST.get("body", "")
        author = request.POST.get("author", "anon")[:80]
    body = body.strip()
    if not body:
        return JsonResponse({"ok": False, "error": "body required"}, status=400)
    Comment.objects.create(author=author, body=body, approved=False)
    return JsonResponse({"ok": True, "queued_for_moderation": True})


@require_GET
def moderate(request):
    """Admin-only moderation queue. VULNERABILITY: the template renders each
    pending comment body with `|safe`, so stored markup executes. Gated to the
    admin session so only the bot (which holds it) can load it."""
    if not (ADMIN_SESSION and hmac.compare_digest(request.COOKIES.get("session", ""), ADMIN_SESSION)):
        return HttpResponse("forbidden — admin only", status=403, content_type="text/plain")
    pending = Comment.objects.filter(approved=False)[:20]
    return render(request, "moderate.html", {"comments": pending})


@require_GET
def bot_login(request):
    """Bot-only: mint the admin session cookie. Backend-firewalled + BOT_KEY so a
    public visitor cannot request the admin cookie."""
    if not _from_backend(request):
        return HttpResponse("forbidden", status=403, content_type="text/plain")
    if not BOT_KEY or request.GET.get("k", "") != BOT_KEY:
        return HttpResponse("forbidden", status=403, content_type="text/plain")
    resp = HttpResponse("logged in", content_type="text/plain")
    # Non-HttpOnly on purpose (the taught weakness). SameSite=Lax.
    resp.set_cookie("session", ADMIN_SESSION, httponly=False, samesite="Lax")
    return resp


@require_GET
def oob_received(request):
    try:
        with urllib.request.urlopen(f"http://{OOB_HOST}:{OOB_PORT}/received", timeout=5) as r:
            body = r.read()
    except Exception as e:  # noqa: BLE001
        return JsonResponse({"ok": False, "error": str(e)}, status=502)
    return HttpResponse(body, content_type="application/json")


@csrf_exempt
@require_POST
def solve(request):
    try:
        data = json.loads(request.body or b"{}")
    except ValueError:
        data = {}
    submitted = str(data.get("c", "")).strip()
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
        return JsonResponse({"ok": True, "flag": flag})
    return JsonResponse({"ok": False, "error": "that is not the admin session"}, status=403)
