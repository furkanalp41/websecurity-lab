# SPDX-License-Identifier: MIT
"""Acme Intranet staff directory — a whitespace-stripping "WAF" in front of a
numeric SQL injection (CWE-89).

`GET /lookup?id=X` renders a directory row. The `id` value is first run through a
homegrown in-application request filter (`waf_forward`) whose author believed
that "no whitespace means no injection keywords". The filter:

  * treats `+` as an encoded space and deletes it,
  * folds the whitespace escapes it knows about (`%20`, `%09`) into real
    space / tab characters and then strips every literal space and tab, and
  * finally percent-decodes whatever survives and forwards it to the backend.

The surviving bytes are concatenated, with no parameterization, straight into:

    SELECT username,email FROM users WHERE is_admin=0 AND id=<id>

Because `id` sits in a NUMERIC context there is no quote to break out of, but the
filter still has to be defeated: every canonical SQL keyword separator the author
was thinking of is a space or a tab, and both are removed. MySQL, however,
happily accepts other token separators the filter never considered — C-style
comments `/**/`, a raw newline (`%0a`, which the filter does NOT strip), and
parentheses. Any of those reaches the parser with ZERO 0x20 bytes.

`GET /debug?id=X` echoes the EXACT bytes `waf_forward` hands to the backend, so a
learner can prove their payload contains no spaces before firing it at `/lookup`.

`GET /solve?email=<value>` compares the submitted value to the hidden admin row's
email (`users` where `id=1`, a random per-container address) and, on an exact
match, returns the flag read from `$FLAG_PATH`.
"""
import os
import re
import urllib.parse
from html import escape

import pymysql
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "lookupapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "directory"),
}

app = Flask(__name__)

PAGE_HEAD = (
    "<!doctype html><meta charset=utf-8>"
    "<title>Acme Intranet — staff directory</title>"
    "<h1>Acme Intranet</h1>"
    "<p>Staff directory. Look colleagues up by their numeric badge id.</p>"
    "<form action=/lookup method=get>"
    "<input name=id placeholder=id value=2> "
    "<button>Look up</button></form>"
    "<p style=color:gray>Requests are screened by the in-house "
    "<code>waf_forward</code> filter. Use <code>/debug?id=...</code> to see the "
    "exact bytes it forwards to the database.</p>"
)

# The only whitespace percent-escapes the homegrown filter was taught about.
# Note the conspicuous absence of %0a (newline) and %0d — that gap is the bug.
_WS_ESCAPES = re.compile(r"%09|%20", re.IGNORECASE)


def connect() -> pymysql.connections.Connection:
    """Open a fresh connection. caching_sha2_password over plaintext TCP needs
    the `cryptography` package (installed) for the RSA public-key handshake."""
    return pymysql.connect(
        host=DB["host"],
        port=DB["port"],
        user=DB["user"],
        password=DB["password"],
        database=DB["database"],
        autocommit=True,
        connect_timeout=5,
        read_timeout=10,
        write_timeout=10,
        charset="utf8mb4",
    )


def raw_query_value(name: str) -> str:
    """Return the RAW, still-percent-encoded value of a query parameter.

    We deliberately read from `request.query_string` instead of `request.args`
    so that the homegrown filter below operates on the wire bytes exactly as its
    author intended (decoding `%20`/`%09` itself). `partition('=')` splits only on
    the first `=`, so an injected `...WHERE/**/id=1` keeps its own `=` intact.
    """
    qs = request.query_string.decode("latin-1")
    for part in qs.split("&"):
        key, _, value = part.partition("=")
        if key == name:
            return value
    return ""


def waf_forward(raw: str) -> str:
    """The homegrown request "WAF".

    Goal, per the developer who wrote it: guarantee that no whitespace ever
    reaches the SQL layer, on the theory that keywords like ``UNION SELECT`` need
    spaces to work. It returns the exact byte string forwarded to the backend.

    VULNERABILITY (CWE-89): stripping whitespace is NOT a defence against SQL
    injection. MySQL treats ``/**/``, a newline (0x0a), and parentheses as valid
    token separators, and none of those is a space or tab. The filter also never
    parameterizes anything — it is a blacklist bolted in front of raw string
    concatenation.
    """
    s = raw
    # (a) Some clients encode a space as '+': drop it.
    s = s.replace("+", "")
    # (b) Fold the whitespace escapes we know about into real whitespace...
    s = _WS_ESCAPES.sub(
        lambda m: "\t" if m.group(0).lower() == "%09" else " ", s
    )
    # (c) ...then strip every literal space and tab (typed or just-decoded).
    s = s.replace(" ", "").replace("\t", "")
    # (d) Percent-decode whatever is left and hand it to the backend. This is
    #     where %0a becomes a newline and %2f%2a%2a%2f becomes /**/ — separators
    #     the filter above never neutralised.
    return urllib.parse.unquote(s)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Acme Intranet staff directory. Try /lookup?id=2\n",
        mimetype="text/plain",
    )


@app.get("/debug")
def debug() -> Response:
    """Echo the exact bytes the filter forwards to SQL (whitespace-proof oracle)."""
    forwarded = waf_forward(raw_query_value("id"))
    has_space = " " in forwarded
    body = (
        "forwarded-to-backend: " + repr(forwarded) + "\n"
        "contains-0x20-space: " + str(has_space) + "\n"
        "length: " + str(len(forwarded)) + "\n"
    )
    return Response(body, mimetype="text/plain")


@app.get("/lookup")
def lookup() -> Response:
    forwarded = waf_forward(raw_query_value("id"))
    if forwarded == "":
        return Response(PAGE_HEAD, mimetype="text/html")

    # VULNERABILITY (CWE-89): `forwarded` is concatenated straight into the SQL
    # text. The leading `is_admin=0` predicate hides the admin row (id=1) from an
    # honest lookup, but a UNION SELECT that reaches the parser through
    # whitespace-free separators can still read it back.
    sql = (
        "SELECT username, email FROM users "
        "WHERE is_admin=0 AND id=" + forwarded
    )
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    except Exception:  # noqa: BLE001 -- do not leak driver errors (no CWE-209 oracle here)
        return Response(
            PAGE_HEAD + "<p class=error>Lookup failed. Check the badge id.</p>",
            status=400,
            mimetype="text/html",
        )
    finally:
        if conn is not None:
            conn.close()

    items = []
    for r in rows:
        username = "" if r[0] is None else escape(str(r[0]))
        email = "" if r[1] is None else escape(str(r[1]))
        items.append("<li>%s &mdash; %s</li>" % (username, email))
    body = "<ul>" + "".join(items) + "</ul>" if items else "<p>No such colleague.</p>"
    return Response(PAGE_HEAD + "<h2>Directory result</h2>" + body, mimetype="text/html")


@app.get("/solve")
def solve() -> Response:
    email = request.args.get("email", "")
    conn = connect()
    try:
        with conn.cursor() as cur:
            # Parameterized on purpose: /solve is the grader, not the vuln.
            cur.execute("SELECT email FROM users WHERE id=%s LIMIT 1", (1,))
            row = cur.fetchone()
    finally:
        conn.close()
    admin_email = row[0] if row else None
    if admin_email is not None and email == admin_email:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(flag + "\n", mimetype="text/plain")
    return Response("Wrong email.\n", status=403, mimetype="text/plain")
