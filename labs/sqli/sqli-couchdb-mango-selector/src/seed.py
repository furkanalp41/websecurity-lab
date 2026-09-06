# SPDX-License-Identifier: MIT
"""Wait for CouchDB, then create and seed the `restricted` database (idempotent).

Seeding creates:
  * the `restricted` database;
  * a hidden `flag_holder` document (owner="system") carrying a fresh per-container
    `secret` (a 16-hex-char token) — the value the attacker must exfiltrate;
  * a handful of decoy documents owned by "guest" so the intended constraint has
    something legitimate to return;
  * a Mango index on `owner` (best effort) so `_find` selectors resolve cleanly.

The `secret` is generated per container and lives ONLY in CouchDB (on a tmpfs).
It is not the flag: the flag is derived from LAB_USER_SECRET at container start
and handed out by /solve once the correct secret is submitted. Re-running the seed
never rotates an existing secret, so it is safe on app restarts.
"""
import os
import secrets
import sys
import time

import httpx

COUCHDB_URL = os.environ.get("COUCHDB_URL", "http://db:5984").rstrip("/")
COUCHDB_USER = os.environ.get("COUCHDB_USER", "labadmin")
COUCHDB_PASSWORD = os.environ.get("COUCHDB_PASSWORD", "")
COUCHDB_DB = os.environ.get("COUCHDB_DB", "restricted")

DECOYS = [
    {
        "_id": "note-welcome",
        "owner": "guest",
        "title": "Welcome to your vault",
        "body": "This is your personal document space. Only you can see these notes.",
    },
    {
        "_id": "note-todo",
        "owner": "guest",
        "title": "TODO",
        "body": "Rotate my API token, tidy up the shared drive.",
    },
    {
        "_id": "note-receipt",
        "owner": "guest",
        "title": "Coffee receipt",
        "body": "Flat white, 4.20. Reimburse later.",
    },
]


def main() -> None:
    client = httpx.Client(
        base_url=COUCHDB_URL, auth=(COUCHDB_USER, COUCHDB_PASSWORD), timeout=10.0
    )

    # 1) Wait for the node to report healthy (public /_up, no auth required).
    for attempt in range(90):
        try:
            r = client.get("/_up")
            if r.status_code == 200:
                break
        except Exception:  # noqa: BLE001 -- CouchDB may still be starting
            pass
        if attempt == 0:
            print("[seed] waiting for couchdb...", flush=True)
        time.sleep(1)
    else:
        sys.exit("[seed] couchdb never became ready")

    # 2) Create the target database (idempotent: 412 == already exists).
    r = client.put(f"/{COUCHDB_DB}")
    if r.status_code not in (201, 202, 412):
        sys.exit(f"[seed] failed to create db: {r.status_code} {r.text}")

    # 3) Seed the hidden flag_holder document, but never rotate an existing secret.
    existing = client.get(f"/{COUCHDB_DB}/{'flag_holder'}")
    if existing.status_code == 200:
        print("[seed] flag_holder already present; secret left unchanged", flush=True)
    else:
        token = secrets.token_hex(8)  # 16 hex chars: short, single-request exfil
        doc = {
            "_id": "flag_holder",
            "owner": "system",
            "classification": "restricted",
            "title": "Master vault credential",
            "secret": token,
            "note": "Internal only. Must never be visible to guest accounts.",
        }
        r = client.put(f"/{COUCHDB_DB}/flag_holder", json=doc)
        if r.status_code not in (201, 202):
            sys.exit(f"[seed] failed to create flag_holder: {r.status_code} {r.text}")

    # 4) Seed decoy guest-owned documents (idempotent by fixed _id).
    for doc in DECOYS:
        rr = client.get(f"/{COUCHDB_DB}/{doc['_id']}")
        if rr.status_code != 200:
            client.put(f"/{COUCHDB_DB}/{doc['_id']}", json=doc)

    # 5) Best-effort Mango index on `owner` so _find selectors resolve cleanly.
    try:
        client.post(
            f"/{COUCHDB_DB}/_index",
            json={"index": {"fields": ["owner"]}, "name": "by-owner", "type": "json"},
        )
    except Exception:  # noqa: BLE001 -- full-scan _find still works without it
        pass

    print("[seed] restricted db ready", flush=True)


if __name__ == "__main__":
    main()
