# SPDX-License-Identifier: MIT
"""Views for the advanced-search lab.

The whole team uses the Django ORM, which parameterises queries by construction —
except for one "advanced search" feature that reached for ``QuerySet.extra()`` to
build a fuzzy ``LIKE`` filter. ``.extra(where=[...])`` takes RAW SQL strings: the
fragment is spliced into the query verbatim, so the ORM's parameterisation is
entirely bypassed. Concatenating the user's ``q`` into that fragment is the bug.
"""
import hmac
import html
import os

from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from app.models import Product

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Catalogue Search</title>"
    "<h1>Catalogue Search</h1>"
    "<p>Internal product catalogue with an <em>advanced fuzzy search</em>.</p>"
    "<ul>"
    "<li><code>GET /search?q=&lt;term&gt;</code> — fuzzy title search</li>"
    "<li><code>POST /solve</code> — field <code>hash</code>: redeem the superuser password hash</li>"
    "</ul>"
    "<form method=get action=/search>"
    "<input name=q placeholder='search titles'>"
    "<button>Search</button>"
    "</form>"
)


def index(request) -> HttpResponse:
    return HttpResponse(_PAGE)


def health(request) -> HttpResponse:
    return HttpResponse("ok", content_type="text/plain")


@require_http_methods(["GET"])
def search(request) -> HttpResponse:
    q = request.GET.get("q", "")
    # VULNERABILITY (CWE-89): .extra(where=[...]) takes a RAW SQL fragment. The
    # ORM does NOT parameterise anything inside it — building the LIKE clause by
    # splicing `q` in with an f-string drops the user straight into the SQL. The
    # doubled `%%` are LIKE wildcards written the way the DBAPI wants them (the
    # driver collapses `%%` -> `%`); they are not what makes this safe or unsafe.
    where_clause = f"title LIKE '%%{q}%%'"
    try:
        products = list(Product.objects.extra(where=[where_clause]))
    except Exception as exc:
        # Verbose errors on purpose (lab aid): surface the DB error so you can
        # tune the injection's column count and types. Do NOT do this in prod.
        return HttpResponse(
            "<!doctype html><meta charset=utf-8><title>Search error</title>"
            "<h1>Search error</h1><pre>%s</pre>" % html.escape(str(exc)),
            status=500,
        )

    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (
            html.escape(str(p.title or "")),
            html.escape(str(p.blurb or "")),
            html.escape("" if p.price_cents is None else "$%.2f" % (p.price_cents / 100)),
        )
        for p in products
    )
    body = (
        "<!doctype html><meta charset=utf-8><title>Search results</title>"
        "<h1>Results</h1>"
        "<table border=1><tr><th>Title</th><th>Description</th><th>Price</th></tr>"
        "%s</table>" % (rows or "<tr><td colspan=3>(no matches)</td></tr>")
    )
    return HttpResponse(body)


@csrf_exempt  # lab simplification: lets the stdlib exploit POST without a token
@require_http_methods(["POST"])
def solve(request) -> JsonResponse:
    submitted = request.POST.get("hash", "")
    # Parameterised on purpose: /solve is NOT the injectable sink. It only checks
    # whether you already exfiltrated the exact superuser hash via /search.
    with connection.cursor() as cursor:
        cursor.execute("SELECT password FROM auth_user WHERE username = %s", ["root"])
        row = cursor.fetchone()
    if row and submitted and hmac.compare_digest(submitted, row[0]):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return JsonResponse({"flag": flag})
    return JsonResponse({"error": "incorrect hash"}, status=403)
