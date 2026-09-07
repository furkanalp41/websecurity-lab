# SPDX-License-Identifier: MIT
"""Acme Metrics — a deliberately vulnerable metrics microservice.

The service connects to PostgreSQL as a **database superuser** (a very common
mis-configuration in Docker'd stacks: the app reuses the POSTGRES_USER role, which
is a superuser). Two endpoints build raw SQL by string concatenation (CWE-89):

  GET  /metrics?category=<c>   ->  results are returned (a VISIBLE injection).
       Runs via asyncpg .fetch(), i.e. the extended (prepared-statement) protocol,
       which permits exactly ONE statement — great for UNION reads, useless for
       stacked statements.

  POST /metrics/ingest {source, category}  ->  fire-and-forget (no rows returned).
       Runs via asyncpg .execute(), i.e. the SIMPLE query protocol, which DOES
       allow multiple ';'-separated statements. This is the sink that lets an
       attacker run stacked DDL + COPY ... FROM PROGRAM.

Chaining the two: use /metrics/ingest to stack
`CREATE TABLE loot(...); COPY loot FROM PROGRAM 'cat /labflag/flag.txt'`, executing
a shell command INSIDE the Postgres container (COPY FROM PROGRAM is superuser-only),
then UNION-read the loot table through the visible GET /metrics. The flag is
planted on the Postgres container's filesystem (see seed.py), never in a table, so
only command execution recovers it.

POST /solve {"flag": "..."} compares against the app-local flag copy (a fixed,
parameterised read — /solve is NOT injectable) and, on a match, returns the flag
plus a signed completion token.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "user": os.environ.get("DB_USER", "metrics"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "metrics"),
}

# Opaque per-process key for the completion token. Not a security control — just a
# signed "you solved it" receipt for the challenge platform.
_COMPLETION_KEY = secrets.token_bytes(32)


def _read_flag() -> str:
    try:
        with open(FLAG_PATH, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _completion_jwt(subject: str) -> str:
    """Minimal HS256 JWT (stdlib only) — a signed completion receipt."""
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": subject, "status": "completed"}).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = b64(hmac.new(_COMPLETION_KEY, signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(**DB, min_size=1, max_size=8)
    try:
        yield
    finally:
        await app.state.pool.close()


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health() -> PlainTextResponse:
    return PlainTextResponse("ok")


@app.get("/")
async def index() -> PlainTextResponse:
    return PlainTextResponse(
        "Acme Metrics service.\n"
        "GET  /metrics?category=<c>     list metrics rows (id, name, value)\n"
        "POST /metrics/ingest {source,category}   record a raw ingest event\n"
        "POST /solve {flag}             submit the recovered flag\n"
    )


@app.get("/metrics")
async def metrics(category: str = "web") -> JSONResponse:
    """VISIBLE injection sink. `category` is concatenated straight into the SQL
    and executed with .fetch() (single statement; UNION-friendly)."""
    sql = (
        "SELECT id, name, value FROM metrics "
        "WHERE category = '" + category + "' ORDER BY id"
    )
    async with app.state.pool.acquire() as conn:
        try:
            rows = await conn.fetch(sql)
        except Exception as e:  # noqa: BLE001 -- surface the DB error text (visible SQLi)
            return JSONResponse({"ok": False, "error": str(e)}, status_code=200)
    return JSONResponse({"ok": True, "rows": [dict(r) for r in rows]})


@app.post("/metrics/ingest")
async def ingest(request: Request) -> JSONResponse:
    """STACKED-CAPABLE injection sink. `source` is concatenated into an INSERT and
    executed with .execute() (simple query protocol → multiple ';' statements
    allowed). Returns no rows: this is the RCE-planting sink, not the readback."""
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    source = str(body.get("source", ""))
    category = str(body.get("category", "web"))
    sql = (
        "INSERT INTO events (source, category) VALUES ('"
        + source + "', '" + category + "')"
    )
    async with app.state.pool.acquire() as conn:
        try:
            await conn.execute(sql)
        except Exception as e:  # noqa: BLE001
            return JSONResponse({"ok": False, "error": str(e)}, status_code=200)
    return JSONResponse({"ok": True})


@app.post("/solve")
async def solve(request: Request) -> JSONResponse:
    """Submit the recovered flag. Compared against the app-local copy with a
    constant-time check. NOT injectable (no query is built from the input)."""
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    submitted = body.get("flag", "")
    submitted = submitted if isinstance(submitted, str) else str(submitted)

    flag = _read_flag()
    if flag and hmac.compare_digest(flag, submitted.strip()):
        return JSONResponse(
            {"solved": True, "flag": flag, "completion": _completion_jwt("sqli-postgres-copy-program-rce-chain")}
        )
    return JSONResponse({"solved": False, "error": "incorrect flag"}, status_code=403)
