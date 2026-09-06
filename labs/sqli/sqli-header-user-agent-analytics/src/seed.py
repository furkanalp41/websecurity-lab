# SPDX-License-Identifier: MIT
"""Wait for MySQL, then create and seed the analytics tables (idempotent).

A RANDOM per-container secret is generated here and stored in
`settings.master_key`. It never touches the image or the source tree: it lives
only in this container's MySQL data directory (a tmpfs) and can be recovered
solely through the stored (second-order) SQL injection surfaced on
`/admin/insights`. This is why a flag lifted from another learner's instance can
never validate on yours.

Two tables:
  * ua_events(id, ua, seen_at) — the visitor log. Rows are written on every
    request by the app's parameterised (safe) INSERT; a few benign seed rows are
    added here so the dashboard is not empty on first view.
  * settings(id, name, master_key) — one row holding the per-container secret.
"""
import os
import secrets
import time

import pymysql

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "dashapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "analytics"),
}

# Realistic, quote-free seed User-Agents so the breakdown renders cleanly before
# any attacker traffic arrives.
SEED_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Mobile/15E148",
    "curl/8.5.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
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
                "CREATE TABLE IF NOT EXISTS ua_events ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  ua VARCHAR(512) NOT NULL,"
                "  seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS settings ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  name VARCHAR(64) NOT NULL,"
                "  master_key VARCHAR(64) NOT NULL"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )

            cur.execute("SELECT COUNT(*) FROM ua_events")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO ua_events (ua) VALUES (%s)",
                    [(ua,) for ua in SEED_UAS],
                )

            cur.execute("SELECT COUNT(*) FROM settings")
            if cur.fetchone()[0] == 0:
                # 32 lowercase hex chars, unpredictable, unique to this container.
                master_key = secrets.token_hex(16)
                cur.execute(
                    "INSERT INTO settings (name, master_key) VALUES (%s, %s)",
                    ("dashboard master key — do not expose", master_key),
                )
        print("[seed] analytics store ready", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
