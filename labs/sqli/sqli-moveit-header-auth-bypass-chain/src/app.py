# SPDX-License-Identifier: MIT
"""Acme Transfer — a file-transfer appliance with a header SQL injection that
chains into session forgery and authenticated file exfiltration.

Chain (abstracting the shape of CVE-2023-34362, MOVEit Transfer):

1. POST /api/transfer/register enriches an audit log with the caller's
   `X-siLock-Comment` header, concatenated straight into an INSERT and run through
   psycopg2's .execute() — which sends the whole string to Postgres, so multiple
   ';'-separated statements execute. That lets an attacker STACK a second INSERT
   that forges a valid admin session row.

2. GET /files/download?path=confidential/flag.bin requires a valid, non-expired
   session cookie whose row is is_admin=true. Normally only /login (parameterised,
   safe) issues sessions, and the attacker has no credentials — but the forged row
   from step 1 is indistinguishable from a real one.

3. Download the per-container confidential file and prove you exfiltrated it by
   POSTing its SHA-256 to /solve, which returns the flag.
"""
import hashlib
import os

import psycopg2
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
CONF_DIR = os.environ.get("CONF_DIR", "/var/lib/lab/confidential")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "dbname": os.environ.get("DB_NAME", "moveit"),
    "user": os.environ.get("DB_USER", "moveitapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
}

app = Flask(__name__)


def connect():
    conn = psycopg2.connect(connect_timeout=5, **DB)
    conn.autocommit = True
    return conn


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Acme Transfer appliance.\n"
        "POST /api/transfer/register        (records an audit note from the X-siLock-Comment header)\n"
        "POST /login {username,password}     issue a session (staff only)\n"
        "GET  /files/download?path=...        download a file (valid admin session required)\n"
        "POST /solve {sha256}                 submit the SHA-256 of the confidential file\n",
        mimetype="text/plain",
    )


@app.post("/api/transfer/register")
def register() -> Response:
    """Register a transfer and append the caller's comment to the audit log.

    VULNERABILITY (CWE-89): the `X-siLock-Comment` header is concatenated straight
    into an INSERT executed with psycopg2 .execute(), which runs multiple
    ';'-separated statements — so a stacked INSERT into `sessions` is possible.
    """
    comment = request.headers.get("X-siLock-Comment", "")
    client_ip = request.remote_addr or "0.0.0.0"
    sql = (
        "INSERT INTO audit_log (comment, client_ip, created_at) VALUES ('"
        + comment + "', '" + client_ip + "', now())"
    )
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(sql)
    except Exception as e:  # noqa: BLE001 -- surface DB errors (this is a visible-ish sink)
        return Response('{"ok": false, "error": %r}' % str(e), mimetype="application/json", status=200)
    finally:
        if conn is not None:
            conn.close()
    return Response('{"ok": true}', mimetype="application/json")


def _valid_admin_session(token: str) -> bool:
    if not token:
        return False
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            # CORRECT, parameterised lookup — the session STORE is the injection
            # target (via the audit sink), not this read.
            cur.execute(
                "SELECT 1 FROM sessions WHERE token = %s AND is_admin = true "
                "AND expires > now() LIMIT 1",
                (token,),
            )
            return cur.fetchone() is not None
    except Exception:  # noqa: BLE001
        return False
    finally:
        if conn is not None:
            conn.close()


@app.get("/files/download")
def download() -> Response:
    token = request.cookies.get("moveit_session", "")
    if not _valid_admin_session(token):
        return Response('{"ok": false, "error": "admin session required"}',
                        mimetype="application/json", status=403)
    path = request.args.get("path", "")
    # Only the confidential file is served, resolved by basename (no traversal).
    if os.path.basename(path) != "flag.bin" or "confidential" not in path:
        return Response('{"ok": false, "error": "not found"}',
                        mimetype="application/json", status=404)
    try:
        with open(os.path.join(CONF_DIR, "flag.bin"), "rb") as fh:
            data = fh.read()
    except OSError:
        return Response('{"ok": false, "error": "unavailable"}',
                        mimetype="application/json", status=500)
    return Response(data, mimetype="application/octet-stream")


@app.post("/login")
def login() -> Response:
    """Issue a session for a real staff account. Parameterised and safe; the
    attacker has no credentials, which is why the audit-log injection (forging a
    session row directly) is the intended path."""
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT is_admin FROM users WHERE username = %s AND password = %s",
                (username, password),
            )
            row = cur.fetchone()
    except Exception:  # noqa: BLE001
        row = None
    finally:
        if conn is not None:
            conn.close()
    if row is None:
        return Response('{"ok": false, "error": "invalid credentials"}',
                        mimetype="application/json", status=401)
    return Response('{"ok": false, "error": "sso handshake required (staff portal)"}',
                    mimetype="application/json", status=403)


@app.post("/solve")
def solve() -> Response:
    body = request.get_json(silent=True) or {}
    submitted = str(body.get("sha256", "")).strip().lower()
    try:
        with open(os.path.join(CONF_DIR, "flag.bin"), "rb") as fh:
            expected = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return Response('{"ok": false, "error": "file unavailable"}',
                        mimetype="application/json", status=500)
    if submitted and submitted == expected:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response('{"ok": true, "flag": "%s"}' % flag, mimetype="application/json")
    return Response('{"ok": false, "error": "hash mismatch"}',
                    mimetype="application/json", status=403)
