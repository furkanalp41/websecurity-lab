# SPDX-License-Identifier: MIT
"""Wait for MySQL, then create and seed the staff directory (idempotent).

A RANDOM per-container admin email is generated here and stored on the row with
`id=1` (`is_admin=1`). It never touches the image or the source tree: it lives
only in this container's MySQL data directory (a tmpfs) and can be recovered only
by defeating the whitespace filter in front of /lookup. That is why a value
lifted from another learner's instance can never validate on yours.
"""
import os
import secrets
import time

import pymysql

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "lookupapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "directory"),
}

# Public directory rows (is_admin=0). The admin row (id=1) is inserted separately
# below with a random email and is deliberately hidden from honest lookups.
MEMBERS = [
    (2, "alice", "alice@acme.example", 0),
    (3, "bob", "bob@acme.example", 0),
    (4, "carol", "carol@acme.example", 0),
    (5, "dave", "dave@acme.example", 0),
]


def connect() -> pymysql.connections.Connection:
    return pymysql.connect(
        host=DB["host"],
        port=DB["port"],
        user=DB["user"],
        password=DB["password"],
        database=DB["database"],
        autocommit=True,
        connect_timeout=5,
        charset="utf8mb4",
    )


def main() -> None:
    conn = None
    for attempt in range(60):
        try:
            conn = connect()
            break
        except Exception:  # noqa: BLE001 -- transient startup errors while MySQL boots
            if attempt == 0:
                print("[seed] waiting for database...", flush=True)
            time.sleep(1)
    if conn is None:
        raise SystemExit("[seed] database never became ready")

    try:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "  id INT PRIMARY KEY,"
                "  username VARCHAR(64) NOT NULL,"
                "  email VARCHAR(128) NOT NULL,"
                "  is_admin TINYINT(1) NOT NULL DEFAULT 0"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )

            cur.execute("SELECT COUNT(*) FROM users")
            if cur.fetchone()[0] == 0:
                # Random, unpredictable admin address unique to this container.
                # secrets.token_hex(8) -> exactly 16 lowercase hex chars.
                admin_email = "admin-%s@lab.internal" % secrets.token_hex(8)
                cur.execute(
                    "INSERT INTO users (id, username, email, is_admin) "
                    "VALUES (%s, %s, %s, %s)",
                    (1, "admin", admin_email, 1),
                )
                cur.executemany(
                    "INSERT INTO users (id, username, email, is_admin) "
                    "VALUES (%s, %s, %s, %s)",
                    MEMBERS,
                )
        print("[seed] directory ready", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
