# SPDX-License-Identifier: MIT
"""Wait for MySQL, then create and seed the helpdesk tables (idempotent).

A RANDOM per-container secret is generated here and stored in
`secrets.api_key` as a version-4 UUID (36 characters). It never touches the
image or the source tree: it lives only in this container's MySQL data
directory (a tmpfs) and can be recovered solely through the error-based SQL
injection in /tickets. This is why a key lifted from another learner's instance
can never validate on yours.
"""
import os
import time
import uuid

import pymysql

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "deskapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "helpdesk"),
}

TICKETS = [
    ("Printer on 3rd floor jams", "open", "alice"),
    ("VPN drops every hour", "in-progress", "alice"),
    ("Onboard new starter laptop", "open", "bob"),
    ("Reset shared mailbox password", "closed", "carol"),
    ("Migrate wiki to new domain", "in-progress", "bob"),
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
                "CREATE TABLE IF NOT EXISTS tickets ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  subject VARCHAR(200) NOT NULL,"
                "  status VARCHAR(32) NOT NULL,"
                "  assignee VARCHAR(64) NOT NULL"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS secrets ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  label VARCHAR(200) NOT NULL,"
                "  api_key VARCHAR(64) NOT NULL"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )

            cur.execute("SELECT COUNT(*) FROM tickets")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO tickets (subject, status, assignee) "
                    "VALUES (%s, %s, %s)",
                    TICKETS,
                )

            cur.execute("SELECT COUNT(*) FROM secrets")
            if cur.fetchone()[0] == 0:
                # A version-4 UUID: 36 characters, unpredictable, unique to this
                # container. Longer than EXTRACTVALUE's 32-char error window, so
                # extracting it requires SUBSTRING chunking.
                api_key = str(uuid.uuid4())
                cur.execute(
                    "INSERT INTO secrets (label, api_key) VALUES (%s, %s)",
                    ("internal billing API key — do not expose", api_key),
                )
        print("[seed] helpdesk ready", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
