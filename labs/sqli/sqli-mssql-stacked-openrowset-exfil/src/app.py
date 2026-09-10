# SPDX-License-Identifier: MIT
"""Acme Asset Inventory — an internal asset tracking system backed by MSSQL 2022.

The endpoint:
    GET /assets?category=<c>
concatenates `category` into a query and runs it through pyodbc. There is:
  - no result echo (the handler returns a fixed "found N assets" count),
  - no error text (all exceptions are swallowed and reported as "server error"),
  - random 100..600ms jitter so timing-based extraction is impractical.

The DB connection uses the SA login (sysadmin). pyodbc with ODBC Driver 18
sends the full SQL batch to MSSQL, which evaluates every semicolon-separated
statement — so stacked queries work. The student can:
  1. Stack an INSERT that copies secrets.mssql_secret into the notices table.
  2. Read it back via GET /notices (which the app exposes for legitimate use).
  3. POST /solve with the recovered 32-hex secret.

Advanced alternative: enable OPENROWSET via sp_configure and demonstrate
arbitrary file read from the DB filesystem.
"""
import json
import os
import random
import time

import pyodbc
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
DB_HOST = os.environ.get("DB_HOST", "db")
DB_PORT = os.environ.get("DB_PORT", "1433")
DB_NAME = os.environ.get("DB_NAME", "inventory")
DB_USER = os.environ.get("DB_USER", "sa")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

CONN_STR = (
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
    f"SERVER={DB_HOST},{DB_PORT};"
    f"DATABASE={DB_NAME};"
    f"UID={DB_USER};PWD={DB_PASSWORD};"
    f"TrustServerCertificate=yes;"
    f"Encrypt=no;"
)

app = Flask(__name__)


def connect() -> pyodbc.Connection:
    return pyodbc.connect(CONN_STR, autocommit=True)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Acme Asset Inventory.\n"
        "GET  /assets?category=<c>   count of assets in a category\n"
        "GET  /notices                company notices\n"
        "POST /solve   {secret}      submit the recovered mssql_secret\n",
        mimetype="text/plain",
    )


@app.get("/assets")
def assets() -> Response:
    """VULNERABILITY: `category` is concatenated into a query. The response is
    normalised to "found N assets" — rows never reach the client, errors are
    hidden, and random jitter kills the timing channel. But stacked queries
    execute every statement in the batch as a side effect."""
    category = request.args.get("category", "")
    time.sleep(0.1 + random.random() * 0.5)
    sql = "SELECT COUNT(*) FROM assets WHERE category = '" + category + "'"
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(sql)
        count = cursor.fetchone()[0]
    except Exception:
        return Response(
            json.dumps({"ok": False, "error": "server error"}),
            mimetype="application/json",
            status=200,
        )
    finally:
        if conn is not None:
            conn.close()
    return Response(
        json.dumps({"ok": True, "message": "found %d assets" % int(count)}),
        mimetype="application/json",
    )


@app.get("/notices")
def notices() -> Response:
    """Read company notices. This is the legitimate data channel the student
    can abuse as an exfiltration sink via stacked INSERT."""
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, title, body, posted_at FROM notices ORDER BY id DESC"
        )
        rows = []
        for row in cursor.fetchall():
            rows.append({
                "id": row[0],
                "title": row[1],
                "body": row[2],
                "posted_at": str(row[3]) if row[3] else None,
            })
    except Exception:
        return Response(
            json.dumps({"ok": False, "error": "server error"}),
            mimetype="application/json",
            status=500,
        )
    finally:
        if conn is not None:
            conn.close()
    return Response(
        json.dumps({"ok": True, "notices": rows}),
        mimetype="application/json",
    )


@app.post("/solve")
def solve() -> Response:
    body = request.get_json(silent=True) or {}
    submitted = str(body.get("secret", "")).strip().lower()
    conn = None
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute("SELECT mssql_secret FROM secrets WHERE id = 1")
        row = cursor.fetchone()
        expected = row[0] if row else ""
    except Exception:
        return Response(
            json.dumps({"ok": False, "error": "server error"}),
            mimetype="application/json",
            status=500,
        )
    finally:
        if conn is not None:
            conn.close()
    import hmac as _hmac
    if submitted and expected and _hmac.compare_digest(submitted, expected.lower()):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(
            json.dumps({"ok": True, "flag": flag}),
            mimetype="application/json",
        )
    return Response(
        json.dumps({"ok": False, "error": "incorrect secret"}),
        mimetype="application/json",
        status=403,
    )
