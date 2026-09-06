# SPDX-License-Identifier: MIT
"""Pulse — a deliberately vulnerable "silent" analytics beacon (time-based blind SQLi).

`GET /beacon?ref=<value>` records a page-view hit and ALWAYS answers `204 No
Content`: no body, no result rows, no error text, and no response header that
varies with the input. Behind it, the handler builds — by raw string
concatenation (CWE-89) — an INSERT statement:

    INSERT INTO hits (referrer, ua) VALUES ('<ref>', '<request User-Agent>')

Because the statement is an INSERT (not a SELECT) and the endpoint returns
nothing, the usual channels are gone: there is no visible column to UNION into,
no echoed row, and no leaked SQL error. The ONLY observable that changes with the
injected SQL is **how long the request takes**. That makes this a textbook
*time-based blind* injection: smuggle a conditional `SLEEP()` into the statement
via a scalar subquery in the VALUES list, and read each answer off the clock.

`POST /solve` accepts JSON `{"token": "<value>"}` and compares it to
`secrets.beacon_token` (a random per-container value seeded at startup). Only on a
match does it read `$FLAG_PATH` and return the flag; otherwise it returns 403.
`/solve` is written the *correct* way (fixed query, value never interpolated) — it
is not the injectable endpoint; `/beacon` is.

Simplification note: the `data/catalog.json` spec sketches a Node/Fastify stack
behind an nginx proxy. This implementation uses the platform's established Python
stack (Flask + gunicorn + PyMySQL) and omits the proxy — a transport detail that
forwards the same `ref` parameter to the same handler. See SOLUTION.md.
"""
import os

import pymysql
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "beaconapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "beacondb"),
}

app = Flask(__name__)


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
        read_timeout=15,
        write_timeout=15,
        charset="utf8mb4",
    )


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Pulse analytics beacon.\n"
        "Fire a page-view with GET /beacon?ref=<referrer>. Returns 204 No Content.\n",
        mimetype="text/plain",
    )


@app.get("/beacon")
def beacon() -> Response:
    """Record an analytics hit and return 204 No Content, always.

    The referrer (`ref` query param) and the request `User-Agent` are logged into
    the `hits` table. This is the vulnerable write path.
    """
    ref = request.args.get("ref", "")
    ua = request.headers.get("User-Agent", "")
    # VULNERABILITY (CWE-89): `ref` and `ua` are concatenated straight into the
    # INSERT text with no quoting, parameterization, or allowlisting. A single
    # quote in `ref` closes the string literal, and the rest of the value is
    # parsed as SQL — including a `(SELECT ... SLEEP() ...)` subquery in the
    # VALUES list.
    sql = (
        "INSERT INTO hits (referrer, ua) VALUES ('"
        + ref + "', '" + ua + "')"
    )
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(sql)
    except Exception:  # noqa: BLE001 -- stay SILENT by design: no error is leaked,
        # so the only side channel an attacker has is the response TIME. A broken
        # or slow query still returns the same empty 204 below.
        pass
    finally:
        if conn is not None:
            conn.close()

    # Always the same response, regardless of success/failure. No body, no
    # varying header: response latency is the sole oracle.
    return Response(status=204)


@app.post("/solve")
def solve() -> Response:
    """Submit the recovered 16-hex beacon token to claim the flag.

    Written the correct way on purpose: the token is compared against a value read
    with a fixed, non-interpolated query. /solve is NOT injectable.
    """
    data = request.get_json(silent=True)
    token = ""
    if isinstance(data, dict):
        raw = data.get("token", "")
        token = raw if isinstance(raw, str) else str(raw)

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT beacon_token FROM secrets LIMIT 1")
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
