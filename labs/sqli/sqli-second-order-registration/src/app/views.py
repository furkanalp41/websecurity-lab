# SPDX-License-Identifier: MIT
"""Views for the referrals lab.

Registration stores the username via the Django ORM (a SAFE, parameterised
INSERT). The vulnerability is second-order: `/me/referrals` later rebuilds a raw
SQL string by concatenating the STORED username, so a payload that was harmless
at write time becomes injectable at read time.
"""
import html
import os

from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import IntegrityError, connection
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Referral Hub</title>"
    "<h1>Referral Hub</h1>"
    "<p>A tiny invite-tracking service.</p>"
    "<ul>"
    "<li><code>POST /register</code> — fields <code>username</code>, <code>password</code></li>"
    "<li><code>POST /login</code> — fields <code>username</code>, <code>password</code></li>"
    "<li><code>GET /me/referrals</code> — your referral codes (login required)</li>"
    "<li><code>GET /solve?secret=&lt;value&gt;</code> — redeem the admin session secret</li>"
    "</ul>"
)


def index(request) -> HttpResponse:
    return HttpResponse(_PAGE)


def health(request) -> HttpResponse:
    return HttpResponse("ok", content_type="text/plain")


@csrf_exempt  # lab simplification: lets the stdlib exploit POST without a token
@require_http_methods(["GET", "POST"])
def register(request) -> HttpResponse:
    if request.method == "GET":
        return HttpResponse(
            "<form method=post><input name=username placeholder=username>"
            "<input name=password type=password placeholder=password>"
            "<button>Register</button></form>"
        )
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    if not username or not password:
        return HttpResponse("username and password required\n", status=400, content_type="text/plain")
    try:
        # SAFE at the write side: the ORM fully parameterises this INSERT, so no
        # amount of quoting in `username` can break out here. The value is NOT
        # validated or neutralised, though — it is stored verbatim.
        User.objects.create_user(username=username, password=password)
    except IntegrityError:
        # Already registered in this container; the caller can just log in.
        pass
    return HttpResponse("registered\n", content_type="text/plain")


@csrf_exempt  # lab simplification: lets the stdlib exploit POST without a token
@require_http_methods(["GET", "POST"])
def login_view(request) -> HttpResponse:
    if request.method == "GET":
        return HttpResponse(
            "<form method=post><input name=username placeholder=username>"
            "<input name=password type=password placeholder=password>"
            "<button>Log in</button></form>"
        )
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    # authenticate() looks the user up through the ORM (parameterised) — safe.
    user = authenticate(request, username=username, password=password)
    if user is None:
        return HttpResponse("invalid credentials\n", status=401, content_type="text/plain")
    login(request, user)
    return HttpResponse("logged in\n", content_type="text/plain")


@login_required
def referrals(request) -> HttpResponse:
    username = request.user.username
    # VULNERABILITY (CWE-89, SECOND-ORDER): the stored username is spliced raw
    # into a SELECT. The source (registration) was parameterised and safe; the
    # dangerous sink is here, and it trusts data that already lives in the DB.
    query = "SELECT code, invited_email FROM referrals WHERE owner = '" + username + "'"
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
    items = "".join(
        "<li><code>%s</code> &mdash; %s</li>"
        % (html.escape(str(row[0])), html.escape(str(row[1] or "")))
        for row in rows
    )
    body = (
        "<!doctype html><meta charset=utf-8><title>Your referrals</title>"
        "<h1>Your referral codes</h1><ul>%s</ul>" % (items or "<li>(none yet)</li>")
    )
    return HttpResponse(body)


@require_http_methods(["GET"])
def solve(request) -> HttpResponse:
    guess = request.GET.get("secret", "")
    # Parameterised on purpose: only /me/referrals is the injectable sink.
    with connection.cursor() as cursor:
        cursor.execute("SELECT session_secret FROM accounts WHERE username = %s", ["admin"])
        row = cursor.fetchone()
    if row and guess and guess == row[0]:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return HttpResponse(flag + "\n", content_type="text/plain")
    return HttpResponse("wrong secret\n", status=403, content_type="text/plain")
