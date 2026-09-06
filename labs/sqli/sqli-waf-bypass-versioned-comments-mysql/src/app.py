# SPDX-License-Identifier: MIT
"""Gizmo Bazaar — deliberately vulnerable product search behind a naive "WAF".

`GET /search?q=X` is fronted by an in-application keyword firewall that mimics a
ModSecurity / OWASP-CRS deployment. BEFORE the query is built, the *raw* value of
`q` is matched against a set of case-insensitive rules; a hit returns HTTP 403 and
is recorded so `GET /waf-log` can show which rule fired. The rules match SQL
keywords as *whole words* (``\\bSELECT\\b``, ``\\bUNION\\b``, ``\\bFROM\\b`` …) plus
the comment sequences ``-- `` and ``#``.

If nothing fires, `X` is concatenated straight into the SQL text (CWE-89):

    SELECT name, price FROM products WHERE name LIKE '%X%'

The MySQL 8 backend evaluates keywords hidden inside *versioned* comments —
``/*!50000SELECT*/`` runs as ``SELECT`` on any server >= 5.0.0 — but the WAF's
whole-word regex never sees a bare ``SELECT`` because the digits are glued to it
(``50000SELECT`` has no word boundary before ``S``). That mismatch is the whole
lab: the same statement the WAF blocks in the clear sails straight through once
its keywords are wrapped in versioned comments and the string literal is
re-balanced (no ``-- `` / ``#`` terminator needed).

`GET /solve?flag=<value>` (``?token=`` also accepted) compares the submitted value
to `secrets.waf_bypass_flag` (a random per-container value seeded at startup) and,
on a match, returns the flag read from `$FLAG_PATH`.
"""
import json
import os
import re
from html import escape

import pymysql
from flask import Flask, Response, request

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "shopapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "storefront"),
}

app = Flask(__name__)

# ---------------------------------------------------------------------------
# The "WAF": a naive keyword firewall modelled on OWASP CRS 942xxx SQLi rules.
#
# Each rule matches a bare SQL token as a WHOLE WORD (\b...\b) or a comment
# marker. Whole-word matching is exactly the blind spot this lab teaches: a
# keyword wrapped in a MySQL versioned comment (/*!50000SELECT*/) carries no
# word boundary before the keyword (the digits are word characters), so \bSELECT\b
# never matches it -- yet MySQL still executes it.
# ---------------------------------------------------------------------------
WAF_RULES = [
    ("942100", "SQL Injection Attack: UNION keyword detected", re.compile(r"\bunion\b", re.I)),
    ("942110", "SQL Injection Attack: SELECT keyword detected", re.compile(r"\bselect\b", re.I)),
    ("942120", "SQL Injection Attack: FROM keyword detected", re.compile(r"\bfrom\b", re.I)),
    ("942130", "SQL Injection Attack: WHERE keyword detected", re.compile(r"\bwhere\b", re.I)),
    ("942140", "SQL Injection Attack: boolean operator (OR/AND) detected", re.compile(r"\b(?:or|and)\b", re.I)),
    ("942150", "SQL Injection Attack: DML/DDL keyword detected", re.compile(r"\b(?:insert|update|delete|drop|alter|create|truncate)\b", re.I)),
    ("942160", "SQL Injection Attack: time-based keyword detected", re.compile(r"\b(?:sleep|benchmark|waitfor)\b", re.I)),
    ("942200", "SQL Comment Sequence Detected: '-- '", re.compile(r"--\s")),
    ("942210", "SQL Comment Sequence Detected: '#'", re.compile(r"#")),
]

PAGE_HEAD = (
    "<!doctype html><meta charset=utf-8>"
    "<title>Gizmo Bazaar — search</title>"
    "<h1>Gizmo Bazaar</h1>"
    "<p>Gadgets, cables, and questionable impulse buys.</p>"
    "<p><small>Requests are inspected by <code>gizmo-waf</code> (CRS-style). "
    "Blocked? See <a href=/waf-log>/waf-log</a>.</small></p>"
    "<form action=/search method=get>"
    "<input name=q placeholder=search value=phone> "
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


def waf_scan(value: str):
    """Return the list of (rule_id, message) that fire on `value`."""
    return [(rid, msg) for (rid, msg, rx) in WAF_RULES if rx.search(value)]


def record_block(value: str, fired) -> None:
    """Persist a blocked request to the shared `waf_log` table so /waf-log can
    report it regardless of which gunicorn worker handled /search. Best-effort:
    a logging failure must never change the WAF's decision."""
    try:
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO waf_log (input_excerpt, rules) VALUES (%s, %s)",
                    (
                        value[:200],
                        json.dumps([{"id": rid, "msg": msg} for (rid, msg) in fired]),
                    ),
                )
                # Keep the table tiny on the tmpfs datadir: retain the newest 50.
                cur.execute(
                    "DELETE FROM waf_log WHERE id <= "
                    "(SELECT * FROM (SELECT MAX(id) - 50 FROM waf_log) t)"
                )
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 -- logging is best-effort, never fatal
        pass


@app.get("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


@app.get("/")
def index() -> Response:
    return Response(
        "Gizmo Bazaar product search. Try /search?q=phone\n"
        "Requests pass through gizmo-waf; /waf-log shows the last blocked rules.\n",
        mimetype="text/plain",
    )


@app.get("/search")
def search() -> Response:
    q = request.args.get("q", "")

    # ---- WAF stage (runs BEFORE the query is assembled) --------------------
    fired = waf_scan(q)
    if fired:
        record_block(q, fired)
        rule_html = "".join(
            "<li><code>%s</code> — %s</li>" % (escape(rid), escape(msg))
            for (rid, msg) in fired
        )
        return Response(
            PAGE_HEAD
            + "<h2>Request blocked by gizmo-waf (403)</h2>"
            + "<p>The following rule(s) fired on your input:</p>"
            + "<ul>" + rule_html + "</ul>"
            + "<p>Inspect recent blocks at <a href=/waf-log>/waf-log</a>.</p>",
            status=403,
            mimetype="text/html",
        )

    # ---- Vulnerable query stage -------------------------------------------
    # VULNERABILITY (CWE-89): `q` is concatenated straight into the SQL text
    # inside a LIKE literal, with no parameterization or escaping. Because the
    # WAF above only rejects *bare* keywords, an attacker who hides UNION/SELECT/
    # FROM inside MySQL versioned comments (/*!50000UNION*/) reaches this line
    # with a fully weaponised payload.
    sql = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001 -- surfaced to help learners debug payloads
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
        name = "" if r[0] is None else escape(str(r[0]))
        price = "" if r[1] is None else escape(str(r[1]))
        items.append("<li>%s — $%s</li>" % (name, price))
    body = "<ul>" + "".join(items) + "</ul>" if items else "<p>No products found.</p>"
    return Response(
        PAGE_HEAD + "<h2>Results for: " + escape(q) + "</h2>" + body,
        mimetype="text/html",
    )


@app.get("/waf-log")
def waf_log() -> Response:
    """Return the most recently fired WAF rules so learners can confirm exactly
    what tripped (and, once they switch to versioned comments, that nothing
    does). Read from the shared table so it is worker-independent."""
    conn = None
    try:
        conn = connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, input_excerpt, rules, created_at "
                "FROM waf_log ORDER BY id DESC LIMIT 10"
            )
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        return Response(
            json.dumps({"error": str(exc)}),
            status=500,
            mimetype="application/json",
        )
    finally:
        if conn is not None:
            conn.close()

    entries = []
    for rid, excerpt, rules_json, created in rows:
        try:
            rules = json.loads(rules_json) if rules_json else []
        except (TypeError, ValueError):
            rules = []
        entries.append(
            {
                "id": rid,
                "input": excerpt,
                "rules": rules,
                "at": created.isoformat() if created is not None else None,
            }
        )
    return Response(
        json.dumps({"blocked": entries}, indent=2) + "\n",
        mimetype="application/json",
    )


@app.get("/solve")
def solve() -> Response:
    # Accept either ?flag= or ?token= (both name the same value).
    value = request.args.get("flag")
    if value is None:
        value = request.args.get("token", "")
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT waf_bypass_flag FROM secrets LIMIT 1")
            row = cur.fetchone()
    finally:
        conn.close()
    secret = row[0] if row else None
    if secret is not None and value == secret:
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return Response(flag + "\n", mimetype="text/plain")
    return Response("Wrong value.\n", status=403, mimetype="text/plain")
