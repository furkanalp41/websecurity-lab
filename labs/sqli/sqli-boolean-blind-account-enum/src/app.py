# SPDX-License-Identifier: MIT
"""Account-recovery portal — deliberately vulnerable boolean-blind SQL injection.

`POST /forgot` accepts JSON `{"username": ...}` and, to "avoid leaking whether an
account exists", ALWAYS returns HTTP 200 with the same generic body. The developer
believed that made the endpoint safe against username enumeration. Two mistakes
undo that:

  1. The username is spliced into a RAW asyncpg query by string concatenation
     (CWE-89) instead of being bound as a parameter.
  2. A convenience response header, `X-Account-Exists`, is set to "true" whenever
     the WHERE clause matched a row and "false" otherwise (CWE-204). That header
     is a perfect boolean oracle: it reflects the truth value of ANY condition an
     attacker can smuggle into the query, one request at a time.

Together they turn a "safe-looking" reset form into a full boolean-blind read
primitive over the users table. The `/solve` endpoint is intentionally written
the RIGHT way (parameterised) to show the contrast, and only hands back the
per-container flag once the attacker has recovered the admin password_hash prefix
through the oracle above.
"""
import asyncio
import os

import asyncpg
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

DB_URL = os.environ["DATABASE_URL"]
FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

# The first 32 characters of the admin's stored password hash are the secret the
# attacker must reconstruct through the boolean oracle before /solve reveals the flag.
PREFIX_LEN = 32

app = FastAPI()

_pool: asyncpg.Pool | None = None
_pool_lock = asyncio.Lock()


async def get_pool() -> asyncpg.Pool:
    """Lazily create a shared connection pool (one per worker process)."""
    global _pool
    if _pool is None:
        async with _pool_lock:
            if _pool is None:
                _pool = await asyncpg.create_pool(DB_URL, min_size=1, max_size=5)
    return _pool


@app.get("/health")
async def health() -> Response:
    return Response(content="ok", media_type="text/plain")


@app.get("/")
async def index() -> Response:
    return Response(
        content=(
            "Account recovery portal.\n"
            "POST /forgot  {\"username\": \"<name>\"}  to request a reset link.\n"
        ),
        media_type="text/plain",
    )


@app.post("/forgot")
async def forgot(request: Request) -> Response:
    """Password-reset request.

    Always answers with the same generic 200 body so the RESPONSE BODY never tells
    you whether the account exists. The vulnerability lives in (a) how the query is
    built and (b) the X-Account-Exists header.
    """
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001 -- malformed JSON is treated as "no account"
        data = {}
    username = ""
    if isinstance(data, dict):
        raw = data.get("username", "")
        username = raw if isinstance(raw, str) else str(raw)

    # VULNERABILITY (CWE-89): the username is concatenated straight into the SQL
    # statement with no parameterization, escaping, or allowlist. Anything the
    # caller sends becomes part of the query text.
    sql = "SELECT 1 FROM users WHERE username = '" + username + "'"

    exists = False
    try:
        pool = await get_pool()
        rows = await pool.fetch(sql)
        exists = len(rows) > 0
    except Exception:  # noqa: BLE001 -- stay "blind": a broken query just reads as false
        exists = False

    # VULNERABILITY (CWE-204): this header leaks the boolean result of the query,
    # turning the endpoint into a truth-value oracle for arbitrary injected conditions.
    headers = {"X-Account-Exists": "true" if exists else "false"}
    return JSONResponse(
        content={"message": "If an account exists, an email has been sent."},
        status_code=200,
        headers=headers,
    )


@app.post("/solve")
async def solve(request: Request) -> Response:
    """Submit the recovered 32-char admin password_hash prefix to claim the flag.

    Written the correct way (parameterised query) on purpose — /solve is NOT the
    injectable endpoint; /forgot is.
    """
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        data = {}
    submitted = ""
    if isinstance(data, dict):
        raw = data.get("prefix", "")
        submitted = raw if isinstance(raw, str) else str(raw)

    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT password_hash FROM users WHERE username = $1", "admin"
    )
    real_prefix = "" if row is None else str(row["password_hash"])[:PREFIX_LEN]

    if submitted == real_prefix and real_prefix != "":
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return JSONResponse(content={"flag": flag}, status_code=200)

    return JSONResponse(content={"ok": False}, status_code=200)
