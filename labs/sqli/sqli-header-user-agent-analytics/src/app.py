# SPDX-License-Identifier: MIT
"""Pulse Metrics — deliberately vulnerable visitor-analytics dashboard.

This lab teaches a **stored / second-order** SQL injection whose *source* and
*sink* live on two completely different code paths, and whose injection surface
is an **HTTP request header** (User-Agent) rather than a query-string parameter.

WRITE path (safe):
    Every request to the site is logged by `log_user_agent()` via a fully
    PARAMETERISED INSERT into `ua_events(id, ua, seen_at)`. The User-Agent is
    stored *verbatim* — quotes and all — and NOTHING is exploitable here. This is
    only the surface: the attacker fully controls the header value.

READ path (vulnerable, CWE-89):
    `GET /admin/insights` builds its per-UA breakdown by RAW STRING CONCATENATION
    of each stored UA value:

        SELECT COUNT(*) FROM ua_events WHERE ua='<stored_ua>'

    A UA that was stored earlier as

        ' UNION SELECT master_key FROM settings-- -

    therefore executes when the dashboard is rendered, and the per-container
    `settings.master_key` is disclosed among the rendered rows. Output is
    HTML-escaped purely to avoid an *unintended* XSS side quest; the leaked key
    (32 hex chars) is still trivially extractable.

`GET|POST /solve?key=<value>` compares the submitted value to
`settings.master_key` (random per container, seeded at startup) and, on a match,
returns the flag read from `$FLAG_PATH`.

Simplification note: the catalogue sketches a Ruby/Sinatra/Sequel stack behind an
internal-only admin panel. This implementation uses the platform's standard
Python/Flask + hardened MySQL stack, and exposes `/admin/insights` directly for
grading (documented as a "debug route" in README.md). Neither choice changes the
vulnerability, the payload, or the fix. See SOLUTION.md.
"""
import os
from html import escape

import pymysql
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "dashapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "analytics"),
}

app = Flask(__name__)

PAGE_HEAD = (
    "<!doctype html><meta charset=utf-8>"
    "<title>Pulse Metrics</title>"
    "<h1>Pulse Metrics</h1>"
    "<p>Lightweight visitor analytics for the marketing team.</p>"
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


@app.before_request
def log_user_agent() -> None:
    """WRITE path (the injection SURFACE) — deliberately SAFE.

    Every request's User-Agent is stored verbatim with a bound parameter, so the
    INSERT itself cannot be subverted no matter what the header contains. The
    danger is entirely on the READ path, which later concatenates these stored
    values into SQL. Logging is best-effort: a hiccup here must never take the
    site down, and /health stays decoupled from the database so the container
    healthcheck reflects the web tier only.
    """
    if request.path == "/health":
        return
    ua = request.headers.get("User-Agent", "")
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            # PARAMETERISED: `ua` travels as data, never as SQL text. Safe.
            cur.execute(
                "INSERT INTO ua_events (ua, seen_at) VALUES (%s, NOW())",
                (ua,),
            )
    except Exception:  # noqa: BLE001 -- logging is best-effort; never 500 the request
        pass
    finally:
        if conn is not None:
            conn.close()


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Pulse Metrics is running. Your visit (and User-Agent) has been logged.\n"
        "Admins review traffic on the internal dashboard at /admin/insights.\n",
        mimetype="text/plain",
    )


@app.get("/admin/insights")
def insights() -> Response:
    """READ path (VULNERABLE, CWE-89) — the analytics breakdown.

    First it fetches the distinct stored User-Agents (a safe, parameter-free
    aggregate). Then, for each one, it re-queries the exact hit count by gluing
    the *stored* UA value straight into the WHERE clause — a raw concatenation of
    data that an attacker controlled on an earlier request. That is the
    second-order sink: a value that was stored safely is re-used unsafely here.
    """
    conn = None
    rows_out = []
    try:
        conn = connect()
        with conn.cursor() as cur:
            # Safe, static aggregate: the set of distinct UAs to break down.
            # Most-recently-seen first so freshly-logged UAs always appear.
            cur.execute(
                "SELECT ua, COUNT(*) AS hits, MAX(id) AS mid "
                "FROM ua_events GROUP BY ua ORDER BY mid DESC LIMIT 50"
            )
            distinct_uas = [r[0] for r in cur.fetchall()]

            for ua in distinct_uas:
                if ua is None:
                    continue
                # VULNERABILITY (CWE-89): the stored UA value is concatenated
                # straight into the SQL text with no quoting, parameterization,
                # or allowlisting. A UA stored earlier as
                #   ' UNION SELECT master_key FROM settings-- -
                # closes the literal, appends a UNION, and comments out the tail,
                # so it executes here on render (stored / second-order SQLi).
                sql = "SELECT COUNT(*) FROM ua_events WHERE ua='" + ua + "'"
                try:
                    cur.execute(sql)
                    for row in cur.fetchall():
                        rows_out.append((ua, row[0]))
                except Exception:  # noqa: BLE001
                    # A malformed stored value (e.g. a stray quote) must not take
                    # the whole dashboard down. Errors are NOT echoed to the
                    # client, so this lab does not rely on verbose DB errors.
                    rows_out.append((ua, "(query failed)"))
    finally:
        if conn is not None:
            conn.close()

    body_rows = []
    for ua, count in rows_out:
        # HTML-escaped only to avoid an unintended reflected-XSS side quest; a
        # leaked 32-hex master_key survives escaping unchanged.
        body_rows.append(
            "<tr><td><code>%s</code></td><td>%s</td></tr>"
            % (escape(str(ua)), escape(str(count)))
        )
    table = (
        "<table border=1 cellpadding=4>"
        "<thead><tr><th>User-Agent</th><th>Hits</th></tr></thead>"
        "<tbody>" + "".join(body_rows) + "</tbody></table>"
    )
    return Response(
        PAGE_HEAD
        + "<h2>Per-User-Agent breakdown</h2>"
        + "<p><em>Internal use only.</em></p>"
        + table,
        mimetype="text/html",
    )


@app.route("/solve", methods=["GET", "POST"])
def solve() -> Response:
    # Accepts the value from either the query string (?key=) or a POST form body.
    key = request.values.get("key", "")
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT master_key FROM settings LIMIT 1")
            row = cur.fetchone()
    finally:
        conn.close()
    master = row[0] if row else None
    if master is not None and key == master:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(flag + "\n", mimetype="text/plain")
    return Response("Wrong key.\n", status=403, mimetype="text/plain")
