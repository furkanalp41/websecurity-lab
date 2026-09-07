# SPDX-License-Identifier: MIT
"""Wait for Postgres, then create and seed the audit/session/user schema.

No attacker-usable session exists at seed time: the `sessions` table is empty of
admin rows the attacker controls, and the sysadmin `users` row has a random,
unknown password. The only way to an admin session is to FORGE one through the
header SQLi in /api/transfer/register.
"""
import os
import secrets
import time

import psycopg2

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "dbname": os.environ.get("DB_NAME", "moveit"),
    "user": os.environ.get("DB_USER", "moveitapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
}


def connect_with_retry():
    for attempt in range(60):
        try:
            conn = psycopg2.connect(connect_timeout=5, **DB)
            conn.autocommit = True
            return conn
        except Exception:  # noqa: BLE001 -- transient startup errors while PG boots
            if attempt == 0:
                print("[seed] waiting for database...", flush=True)
            time.sleep(1)
    raise SystemExit("[seed] database never became ready")


def main() -> None:
    conn = connect_with_retry()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS audit_log ("
                "  id SERIAL PRIMARY KEY,"
                "  comment TEXT NOT NULL,"
                "  client_ip TEXT NOT NULL,"
                "  created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS sessions ("
                "  token TEXT PRIMARY KEY,"
                "  username TEXT NOT NULL,"
                "  is_admin BOOLEAN NOT NULL DEFAULT false,"
                "  expires TIMESTAMPTZ NOT NULL)"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "  id SERIAL PRIMARY KEY,"
                "  username TEXT UNIQUE NOT NULL,"
                "  password TEXT NOT NULL,"
                "  is_admin BOOLEAN NOT NULL DEFAULT false)"
            )

            cur.execute("SELECT COUNT(*) FROM users")
            if cur.fetchone()[0] == 0:
                # The built-in sysadmin account. Its password is random and never
                # exposed — you cannot log in as it; you must forge its session.
                cur.execute(
                    "INSERT INTO users (username, password, is_admin) VALUES (%s, %s, true)",
                    ("sysadmin", secrets.token_hex(24)),
                )
                cur.execute(
                    "INSERT INTO users (username, password, is_admin) VALUES (%s, %s, false)",
                    ("guest", "guest"),
                )

            cur.execute("SELECT COUNT(*) FROM audit_log")
            if cur.fetchone()[0] == 0:
                cur.execute(
                    "INSERT INTO audit_log (comment, client_ip) VALUES "
                    "('nightly backup complete', '10.0.0.9'),"
                    "('quarterly report uploaded', '10.0.0.14')"
                )
        print("[seed] transfer store ready", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
