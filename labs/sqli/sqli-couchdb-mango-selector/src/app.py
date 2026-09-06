# SPDX-License-Identifier: MIT
"""Document-management API — deliberately vulnerable CouchDB Mango selector injection.

`POST /find` accepts JSON `{"filter": {...}}` and is meant to let a *guest* browse
only their own documents. To enforce that, the service keeps a server-side
row-level constraint, `{"owner": "guest"}`, and — it believes — always applies it
before querying CouchDB's Mango `_find` endpoint on the `restricted` database.

The mistake (CWE-943, NoSQL / query-language injection) is *how* the two are
combined. Instead of composing the constraint and the client filter under a
server-controlled `$and`, the code does a shallow dict merge in which the CLIENT
WINS:

    selector = {**{"owner": "guest"}, **client_filter}

Any key the caller supplies overrides the identically-named key in the
constraint. Sending `{"owner": {"$gt": null}}` replaces `owner == "guest"` with
"owner greater than null" — true for every document — so the selector now matches
the whole database, including the hidden `flag_holder` document
(`owner == "system"`) whose `secret` field is the per-container secret.

`GET /solve?secret=<value>` is written the RIGHT way: it reads the real secret
from the `flag_holder` document with a fixed server-side lookup (no client input
in the query) and, only on a constant-time match, returns the per-container flag
read from `$FLAG_PATH`.
"""
import asyncio
import hmac
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

COUCHDB_URL = os.environ.get("COUCHDB_URL", "http://db:5984").rstrip("/")
COUCHDB_USER = os.environ.get("COUCHDB_USER", "labadmin")
COUCHDB_PASSWORD = os.environ.get("COUCHDB_PASSWORD", "")
COUCHDB_DB = os.environ.get("COUCHDB_DB", "restricted")
FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")

# The row-level access constraint the API is SUPPOSED to enforce for the guest
# caller: results must be limited to documents this account owns.
OWNER_CONSTRAINT = {"owner": "guest"}

# The _id of the hidden document a guest must never reach. Its `secret` field is
# seeded at startup with a fresh per-container token (see seed.py).
FLAG_DOC_ID = "flag_holder"

app = FastAPI()

_client: httpx.AsyncClient | None = None
_client_lock = asyncio.Lock()


async def get_client() -> httpx.AsyncClient:
    """Lazily create one shared authenticated CouchDB client per worker process."""
    global _client
    if _client is None:
        async with _client_lock:
            if _client is None:
                _client = httpx.AsyncClient(
                    base_url=COUCHDB_URL,
                    auth=(COUCHDB_USER, COUCHDB_PASSWORD),
                    timeout=10.0,
                )
    return _client


@app.get("/health")
async def health() -> PlainTextResponse:
    return PlainTextResponse("ok")


@app.get("/")
async def index() -> PlainTextResponse:
    return PlainTextResponse(
        "Document vault API.\n"
        'POST /find  {"filter": {...}}  to search your documents (owner=guest).\n'
        "GET  /solve?secret=<value>     to redeem a recovered secret for the flag.\n"
    )


@app.post("/find")
async def find(request: Request) -> JSONResponse:
    """Search documents in the `restricted` database.

    The caller's `filter` is intended to *narrow* the result set within the
    documents they already own. In reality it is merged OVER the owner constraint,
    so a caller-supplied `owner` key (or any colliding key) silently overrides the
    server's access control and reaches documents belonging to other owners.
    """
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001 -- malformed JSON == empty filter
        data = {}

    client_filter: dict = {}
    if isinstance(data, dict):
        raw = data.get("filter", {})
        if isinstance(raw, dict):
            client_filter = raw

    # VULNERABILITY (CWE-943): shallow "client wins" merge. Keys the caller sends
    # overwrite the server constraint instead of being ANDed under it, so
    # {"owner": {"$gt": null}} erases owner=="guest" and the selector matches the
    # entire database. The correct design composes them server-side, e.g.
    #   {"$and": [OWNER_CONSTRAINT, sanitise(client_filter)]}
    selector = {**OWNER_CONSTRAINT, **client_filter}

    client = await get_client()
    try:
        resp = await client.post(
            f"/{COUCHDB_DB}/_find",
            json={"selector": selector, "limit": 50},
        )
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001 -- surface CouchDB/network errors verbatim
        return JSONResponse({"error": "query failed", "detail": str(exc)}, status_code=502)

    docs = payload.get("docs", []) if isinstance(payload, dict) else []
    # Echo the effective selector back so the merge behaviour is observable.
    return JSONResponse({"selector": selector, "count": len(docs), "docs": docs})


@app.get("/solve")
async def solve(secret: str = "") -> JSONResponse:
    """Redeem a recovered secret for the per-container flag.

    Written the SAFE way: the secret is looked up with a fixed document GET (no
    caller input in the query) and compared in constant time. Only an exact match
    reveals the flag, which is read from a tmpfs file at request time — it is never
    baked into the image or stored in the database.
    """
    client = await get_client()
    try:
        resp = await client.get(f"/{COUCHDB_DB}/{FLAG_DOC_ID}")
        doc = resp.json()
    except Exception:  # noqa: BLE001
        doc = {}

    real_secret = str(doc.get("secret", "")) if isinstance(doc, dict) else ""

    if secret and real_secret and hmac.compare_digest(secret, real_secret):
        try:
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
        except OSError:
            flag = "(flag unavailable)"
        return JSONResponse({"flag": flag})

    return JSONResponse({"ok": False})
