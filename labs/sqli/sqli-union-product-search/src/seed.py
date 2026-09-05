# SPDX-License-Identifier: MIT
"""Wait for MySQL, then create and seed the store tables (idempotent).

A RANDOM per-container secret is generated here and stored in
`admin_notes.secret`. It never touches the image or the source tree: it lives
only in this container's MySQL data directory (a tmpfs) and can be recovered
solely through the UNION-based SQL injection in /search. This is why a flag
lifted from another learner's instance can never validate on yours.
"""
import os
import secrets
import time

import pymysql

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "recordapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "vinylshop"),
}

RECORDS = [
    ("Kind of Blue", "Miles Davis", "jazz", "24.99", 1),
    ("A Love Supreme", "John Coltrane", "jazz", "22.50", 1),
    ("Time Out", "The Dave Brubeck Quartet", "jazz", "21.00", 1),
    ("Rumours", "Fleetwood Mac", "rock", "19.99", 1),
    ("Discovery", "Daft Punk", "electronic", "27.00", 1),
    # released=0 rows exist so the `AND released=1` filter is meaningful.
    ("Lost Sessions (unreleased)", "Miles Davis", "jazz", "0.00", 0),
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
                "CREATE TABLE IF NOT EXISTS records ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  title VARCHAR(200) NOT NULL,"
                "  artist VARCHAR(200) NOT NULL,"
                "  category VARCHAR(64) NOT NULL,"
                "  price DECIMAL(6,2) NOT NULL,"
                "  released TINYINT(1) NOT NULL DEFAULT 1"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS admin_notes ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  note VARCHAR(200) NOT NULL,"
                "  secret VARCHAR(64) NOT NULL"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )

            cur.execute("SELECT COUNT(*) FROM records")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO records (title, artist, category, price, released) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    RECORDS,
                )

            cur.execute("SELECT COUNT(*) FROM admin_notes")
            if cur.fetchone()[0] == 0:
                # 32 lowercase hex chars, unpredictable, unique to this container.
                secret = secrets.token_hex(16)
                cur.execute(
                    "INSERT INTO admin_notes (note, secret) VALUES (%s, %s)",
                    ("internal launch checklist — do not expose", secret),
                )
        print("[seed] store ready", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
