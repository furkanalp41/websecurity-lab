# SPDX-License-Identifier: MIT
"""Streamline — deliberately vulnerable paginated activity feed (LIMIT/OFFSET SQLi).

`GET /feed?page=<n>&size=<m>` builds, by raw string concatenation:

    SELECT title, body FROM feed ORDER BY id LIMIT <size> OFFSET <page>

Both `size` and `page` are spliced straight into the statement with no quoting,
casting, or allowlist (CWE-89). There is no string literal here to break out of,
so the naive `' OR '1'='1` payloads are useless — but the LIMIT and OFFSET
positions accept an arbitrary *integer expression*, including a parenthesised
scalar subquery. Postgres errors are echoed verbatim (CWE-209), so a failed
text->integer CAST placed in the OFFSET position becomes a value oracle.

`GET /solve?code=<value>` compares the submitted value to the admin user's
`recovery_code` (a random per-container secret seeded at startup) and, on a
match, returns the flag read from `$FLAG_PATH` as JSON.
"""
import json
import os

from flask import Flask, Response, request
from sqlalchemy import create_engine, text

DB_URL = os.environ["DATABASE_URL"]
FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

app = Flask(__name__)
engine = create_engine(DB_URL, pool_pre_ping=True)


def _json(payload: dict, status: int = 200) -> Response:
    return Response(json.dumps(payload) + "\n", status=status, mimetype="application/json")


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Streamline activity feed. Try /feed?page=0&size=10\n",
        mimetype="text/plain",
    )


@app.get("/feed")
def feed() -> Response:
    # Intended usage: `page` is the starting record offset (0, 10, 20, ...) and
    # `size` is the page length. The developer "knows" these are always numbers.
    size = request.args.get("size", "10")
    page = request.args.get("page", "0")
    # VULNERABILITY (CWE-89): `size` and `page` are concatenated straight into the
    # LIMIT and OFFSET positions with no casting, parameterization, or allowlist.
    # Placeholders cannot bind here anyway if you try to be "clever" — but the
    # right fix is to coerce to int (see SOLUTION.md), not to concatenate.
    sql = (
        "SELECT title, body FROM feed ORDER BY id "
        "LIMIT " + size + " OFFSET " + page
    )
    try:
        with engine.connect() as conn:
            rows = conn.execute(text(sql)).fetchall()
    except Exception as exc:  # noqa: BLE001 -- verbose errors are the teaching point (CWE-209)
        # Raw Postgres error text is echoed verbatim (information leak, by design).
        return Response("DB error: " + str(exc), status=500, mimetype="text/plain")
    body = "\n".join(f"{r[0]} — {r[1]}" for r in rows)
    return Response("Activity feed\n" + body + "\n", mimetype="text/plain")


@app.get("/solve")
def solve() -> Response:
    guess = request.args.get("code", "")
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT recovery_code FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
        ).fetchone()
    secret = row[0] if row else None
    if secret is not None and guess == secret:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return _json({"flag": flag})
    return _json({"error": "wrong recovery code"}, status=403)
