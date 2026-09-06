# SPDX-License-Identifier: MIT
"""Wait for MySQL, then create and seed the analytics tables (idempotent).

A RANDOM per-container token is generated here and stored in
`secrets.beacon_token`. It never touches the image or the source tree: it lives
only in this container's MySQL data directory (a tmpfs) and can be recovered
solely through the time-based blind SQL injection in /beacon. A flag lifted from
another learner's instance can therefore never validate on yours.

The token is `secrets.token_hex(8)` -> exactly 16 lowercase hex characters. The
catalogue aspirationally specified a 40-character token at ~1 second per bit;
that would push a serial time-based extraction to several minutes, which cannot
pass the platform's "<60s exploit" gate. Shrinking the token to 16 hex chars
(64 bits of entropy) and using a parallelised exploit keeps the wall-clock well
under a minute while leaving the technique identical. See SOLUTION.md.
"""
import os
import secrets
import time

import pymysql

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "beaconapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "beacondb"),
}

# A few realistic-looking historical hits so the table is not empty. None of
# these values matter to the challenge; the token lives in `secrets`.
SEED_HITS = [
    ("https://news.ycombinator.com/", "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"),
    ("https://www.google.com/search?q=pulse+analytics", "Mozilla/5.0 (Macintosh) Safari/17.5"),
    ("https://t.co/aBcD", "Mozilla/5.0 (iPhone) Mobile/15E148"),
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
                "CREATE TABLE IF NOT EXISTS hits ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  referrer VARCHAR(512) NOT NULL,"
                "  ua VARCHAR(512) NOT NULL,"
                "  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS secrets ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  label VARCHAR(200) NOT NULL,"
                "  beacon_token VARCHAR(64) NOT NULL"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )

            cur.execute("SELECT COUNT(*) FROM hits")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO hits (referrer, ua) VALUES (%s, %s)",
                    SEED_HITS,
                )

            cur.execute("SELECT COUNT(*) FROM secrets")
            if cur.fetchone()[0] == 0:
                # 16 lowercase hex chars (64 bits), unpredictable, unique to this
                # container. Recoverable only via the /beacon timing oracle.
                token = secrets.token_hex(8)
                cur.execute(
                    "INSERT INTO secrets (label, beacon_token) VALUES (%s, %s)",
                    ("internal beacon signing token — do not expose", token),
                )
        print("[seed] analytics store ready", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
