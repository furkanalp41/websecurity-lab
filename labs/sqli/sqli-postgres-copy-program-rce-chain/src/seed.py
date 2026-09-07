# SPDX-License-Identifier: MIT
"""Wait for Postgres, seed the metrics schema, and PLANT the flag on the Postgres
container's filesystem via a superuser server-side COPY ... TO write.

Why plant it on the filesystem (not in a table): the whole point of this lab is
COPY ... FROM PROGRAM command execution. If the flag lived in a table it would be
a trivial SQL SELECT. Instead it is written to /labflag/flag.txt INSIDE the
Postgres container and is recoverable only by executing `cat /labflag/flag.txt`
through the RCE.

The flag is derived app-side (entrypoint.sh, from LAB_USER_SECRET) and read here
from FLAG_PATH. The raw LAB_USER_SECRET is NEVER sent to Postgres — so a shell
obtained via the RCE cannot re-derive other learners' flags. It can read this
instance's flag, which is exactly the objective.
"""
import asyncio
import os

import asyncpg

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "user": os.environ.get("DB_USER", "metrics"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "metrics"),
}
FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
PG_FLAG_PATH = os.environ.get("PG_FLAG_PATH", "/labflag/flag.txt")

SEED_METRICS = [
    ("web", "page_views", 128374),
    ("web", "unique_visitors", 40211),
    ("api", "requests_total", 998211),
    ("api", "error_rate_ppm", 342),
    ("billing", "invoices_paid", 5120),
]
SEED_EVENTS = [
    ("cdn-edge-eu", "web"),
    ("mobile-sdk", "api"),
    ("cron-nightly", "billing"),
]


async def connect_with_retry() -> asyncpg.Connection:
    for attempt in range(60):
        try:
            return await asyncpg.connect(**DB)
        except Exception:  # noqa: BLE001 -- transient startup errors while PG boots
            if attempt == 0:
                print("[seed] waiting for database...", flush=True)
            await asyncio.sleep(1)
    raise SystemExit("[seed] database never became ready")


def read_flag() -> str:
    with open(FLAG_PATH, encoding="utf-8") as fh:
        return fh.read().strip()


async def main() -> None:
    conn = await connect_with_retry()
    try:
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS metrics ("
            "  id SERIAL PRIMARY KEY,"
            "  category TEXT NOT NULL,"
            "  name TEXT NOT NULL,"
            "  value BIGINT NOT NULL)"
        )
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "  id SERIAL PRIMARY KEY,"
            "  source TEXT NOT NULL,"
            "  category TEXT NOT NULL,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )

        if await conn.fetchval("SELECT COUNT(*) FROM metrics") == 0:
            await conn.executemany(
                "INSERT INTO metrics (category, name, value) VALUES ($1, $2, $3)",
                SEED_METRICS,
            )
        if await conn.fetchval("SELECT COUNT(*) FROM events") == 0:
            await conn.executemany(
                "INSERT INTO events (source, category) VALUES ($1, $2)",
                SEED_EVENTS,
            )

        # Plant the flag on the Postgres container filesystem. The flag is FLAG{64
        # lowercase hex} — no quotes/backslashes — so a single-quoted literal is
        # safe here. COPY ... TO <path> is a superuser server-side file write.
        flag = read_flag()
        await conn.execute(
            "COPY (SELECT '" + flag + "') TO '" + PG_FLAG_PATH + "' (FORMAT text)"
        )
        print("[seed] metrics store ready; flag planted on the db filesystem", flush=True)
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
