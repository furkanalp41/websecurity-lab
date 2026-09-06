# SPDX-License-Identifier: MIT
"""DeskFlow — deliberately vulnerable ticket dashboard (error-based SQLi).

`GET /tickets?assignee=X` builds, by raw string concatenation:

    SELECT id, subject, status FROM tickets WHERE assignee='X'

`X` is spliced in with no quoting, escaping, or parameterization (CWE-89), so an
attacker can close the string literal and inject SQL. Whenever the query raises,
the raw MySQL error text is rendered verbatim inside a friendly banner (CWE-209).
That verbose error channel is exactly what makes *error-based* extraction work:
`EXTRACTVALUE()` can be coerced into an "XPATH syntax error: ':<value>'" whose
message leaks a subquery result straight back onto the page.

`POST /solve` with a JSON (or form) body `{"key": "<value>"}` compares the
submitted key to `secrets.api_key` (a random per-container UUID seeded at
startup) and, on a match, returns the flag read from `$FLAG_PATH`.

Simplification note: like the other Python SQLi labs, this one omits any nginx
reverse proxy — gunicorn serves port 8080 directly. See SOLUTION.md for why that
changes nothing about the vulnerability.
"""
import os
from html import escape

import pymysql
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "deskapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "helpdesk"),
}

app = Flask(__name__)

PAGE_HEAD = (
    "<!doctype html><meta charset=utf-8>"
    "<title>DeskFlow — tickets</title>"
    "<h1>DeskFlow</h1>"
    "<p>Internal ticket dashboard. Filter the queue by assignee.</p>"
    "<form action=/tickets method=get>"
    "<input name=assignee placeholder=assignee value=alice> "
    "<button>Filter</button></form>"
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
        "DeskFlow ticket dashboard. Try /tickets?assignee=alice\n",
        mimetype="text/plain",
    )


@app.get("/tickets")
def tickets() -> Response:
    assignee = request.args.get("assignee", "")
    # VULNERABILITY (CWE-89): `assignee` is concatenated straight into the SQL
    # text with no quoting, parameterization, or allowlisting. Anything typed
    # here becomes part of the statement, so a `'` closes the literal and the
    # remainder is parsed as SQL — including error-raising functions.
    sql = (
        "SELECT id, subject, status FROM tickets "
        "WHERE assignee='" + assignee + "'"
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
        # the raw error string still leaks subquery results via EXTRACTVALUE's
        # "XPATH syntax error: ':<value>'" message.
        return Response(
            PAGE_HEAD
            + "<p class=error>Query failed — MySQL said: "
            + escape(str(exc))
            + "</p>",
            status=500,
            mimetype="text/html",
        )
    finally:
        if conn is not None:
            conn.close()

    items = []
    for r in rows:
        tid = "" if r[0] is None else escape(str(r[0]))
        subject = "" if r[1] is None else escape(str(r[1]))
        status = "" if r[2] is None else escape(str(r[2]))
        items.append("<li>#%s — %s — [%s]</li>" % (tid, subject, status))
    body = (
        "<ul>" + "".join(items) + "</ul>" if items else "<p>No tickets found.</p>"
    )
    return Response(
        PAGE_HEAD + "<h2>Queue for: " + escape(assignee) + "</h2>" + body,
        mimetype="text/html",
    )


@app.post("/solve")
def solve() -> Response:
    # Accept either a JSON body {"key": "..."} or a form field `key`.
    data = request.get_json(silent=True)
    key = None
    if isinstance(data, dict):
        key = data.get("key")
    if key is None:
        key = request.form.get("key")
    if key is None:
        return Response('Send JSON {"key": "<uuid>"}.\n', status=400, mimetype="text/plain")

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT api_key FROM secrets LIMIT 1")
            row = cur.fetchone()
    finally:
        conn.close()
    api_key = row[0] if row else None
    if api_key is not None and str(key) == api_key:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(flag + "\n", mimetype="text/plain")
    return Response("Wrong key.\n", status=403, mimetype="text/plain")
