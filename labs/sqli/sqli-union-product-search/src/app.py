# SPDX-License-Identifier: MIT
"""Wax & Groove — deliberately vulnerable vinyl-store search (UNION-based SQLi).

`GET /search?category=X` builds, by raw string concatenation:

    SELECT title, artist, price FROM records WHERE category='X' AND released=1

`X` is spliced in with no quoting, escaping, or parameterization (CWE-89), so an
attacker can close the string literal and append a `UNION SELECT`. MySQL errors
are echoed verbatim on the page (CWE-209), which turns column-count and datatype
discovery into a trivial oracle.

`GET /solve?token=<value>` compares the submitted token to `admin_notes.secret`
(a random per-container value seeded at startup) and, on a match, returns the
flag read from `$FLAG_PATH`.

Simplification note: unlike some other labs, this one omits the nginx reverse
proxy — gunicorn serves port 8080 directly. See SOLUTION.md for why that changes
nothing about the vulnerability.
"""
import os
from html import escape

import pymysql
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "recordapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "vinylshop"),
}

app = Flask(__name__)

PAGE_HEAD = (
    "<!doctype html><meta charset=utf-8>"
    "<title>Wax &amp; Groove — search</title>"
    "<h1>Wax &amp; Groove</h1>"
    "<p>Second-hand vinyl, lovingly catalogued.</p>"
    "<form action=/search method=get>"
    "<input name=category placeholder=category value=jazz> "
    "<button>Search</button></form>"
)


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


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Wax & Groove vinyl store. Try /search?category=jazz\n",
        mimetype="text/plain",
    )


@app.get("/search")
def search() -> Response:
    category = request.args.get("category", "")
    # VULNERABILITY (CWE-89): `category` is concatenated straight into the SQL
    # text with no quoting, parameterization, or allowlisting. Anything typed
    # here becomes part of the statement, so a `'` closes the literal and a
    # trailing UNION SELECT is executed as code.
    sql = (
        "SELECT title, artist, price FROM records "
        "WHERE category='" + category + "' AND released=1"
    )
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001 -- verbose errors are the teaching point (CWE-209)
        # MySQL error text is echoed verbatim (information leak, by design). It
        # is HTML-escaped only to avoid an *unintended* reflected-XSS side quest;
        # the raw error string still leaks column counts and datatypes.
        return Response(
            PAGE_HEAD + "<p class=error>MySQL error: " + escape(str(exc)) + "</p>",
            status=500,
            mimetype="text/html",
        )
    finally:
        if conn is not None:
            conn.close()

    items = []
    for r in rows:
        title = "" if r[0] is None else escape(str(r[0]))
        artist = "" if r[1] is None else escape(str(r[1]))
        price = "" if r[2] is None else escape(str(r[2]))
        items.append("<li>%s — %s — $%s</li>" % (title, artist, price))
    body = "<ul>" + "".join(items) + "</ul>" if items else "<p>No records found.</p>"
    return Response(
        PAGE_HEAD + "<h2>Results for: " + escape(category) + "</h2>" + body,
        mimetype="text/html",
    )


@app.get("/solve")
def solve() -> Response:
    token = request.args.get("token", "")
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT secret FROM admin_notes LIMIT 1")
            row = cur.fetchone()
    finally:
        conn.close()
    secret = row[0] if row else None
    if secret is not None and token == secret:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(flag + "\n", mimetype="text/plain")
    return Response("Wrong token.\n", status=403, mimetype="text/plain")
