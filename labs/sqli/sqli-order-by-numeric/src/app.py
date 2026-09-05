# SPDX-License-Identifier: MIT
"""Vintage blog archive — deliberately vulnerable ORDER BY injection.

The `sort` parameter is spliced into an ORDER BY clause unquoted (the developer
"assumed" it is numeric), so tautology payloads fail but expression/CASE-based
injection in the ORDER BY position succeeds. DB errors are echoed verbatim,
which turns a CAST error into a value oracle for current_user.
"""
import os

from flask import Flask, Response, request
from sqlalchemy import create_engine, text

DB_URL = os.environ["DATABASE_URL"]
FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

app = Flask(__name__)
engine = create_engine(DB_URL, pool_pre_ping=True)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response("Vintage blog archive. Try /archive?sort=1\n", mimetype="text/plain")


@app.get("/archive")
def archive() -> Response:
    sort = request.args.get("sort", "1")
    # VULNERABILITY (CWE-89): `sort` concatenated into ORDER BY with no quoting,
    # parameterization, or allowlist.
    sql = "SELECT title, author, published FROM posts ORDER BY " + sort + " ASC"
    try:
        with engine.connect() as conn:
            rows = conn.execute(text(sql)).fetchall()
        body = "\n".join(f"{r[0]} — {r[1]} ({r[2]})" for r in rows)
        return Response("Blog archive\n" + body + "\n", mimetype="text/plain")
    except Exception as exc:  # noqa: BLE001 -- verbose errors are the teaching point
        return Response("DB error: " + str(exc), status=500, mimetype="text/plain")


@app.get("/solve")
def solve() -> Response:
    guess = request.args.get("user", "")
    with engine.connect() as conn:
        current = conn.execute(text("SELECT current_user")).scalar_one()
    if guess == current:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(flag + "\n", mimetype="text/plain")
    return Response("Wrong database user.\n", status=403, mimetype="text/plain")
