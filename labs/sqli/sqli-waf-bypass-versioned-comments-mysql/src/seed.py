# SPDX-License-Identifier: MIT
"""Wait for MySQL, then create and seed the storefront tables (idempotent).

A RANDOM per-container secret is generated here and stored in
`secrets.waf_bypass_flag`. It never touches the image or the source tree: it
lives only in this container's MySQL data directory (a tmpfs) and can be
recovered solely through the WAF-bypassing SQL injection in /search. This is why
a flag lifted from another learner's instance can never validate on yours.
"""
import os
import secrets
import time

import pymysql

DB = {
    "host": os.environ.get("DB_HOST", "db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "shopapp"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "storefront"),
}

PRODUCTS = [
    ("Aurora Wireless Earbuds", "79.99"),
    ("Nimbus USB-C Charger 65W", "34.50"),
    ("Cobalt Mechanical Keyboard", "119.00"),
    ("Halcyon Noise-Cancelling Headphones", "199.99"),
    ("Pebble Portable SSD 1TB", "89.95"),
    ("Lumen Smart Desk Lamp", "42.00"),
    ("Vortex Phone Stand", "14.99"),
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
                "CREATE TABLE IF NOT EXISTS products ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  name VARCHAR(200) NOT NULL,"
                "  price DECIMAL(8,2) NOT NULL"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS secrets ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  label VARCHAR(120) NOT NULL,"
                "  waf_bypass_flag VARCHAR(64) NOT NULL"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS waf_log ("
                "  id INT AUTO_INCREMENT PRIMARY KEY,"
                "  input_excerpt VARCHAR(200) NOT NULL,"
                "  rules TEXT NOT NULL,"
                "  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )

            cur.execute("SELECT COUNT(*) FROM products")
            if cur.fetchone()[0] == 0:
                cur.executemany(
                    "INSERT INTO products (name, price) VALUES (%s, %s)",
                    PRODUCTS,
                )

            cur.execute("SELECT COUNT(*) FROM secrets")
            if cur.fetchone()[0] == 0:
                # 32 lowercase hex chars, unpredictable, unique to this container.
                flag_value = secrets.token_hex(16)
                cur.execute(
                    "INSERT INTO secrets (label, waf_bypass_flag) VALUES (%s, %s)",
                    ("waf-bypass challenge token — do not expose", flag_value),
                )
        print("[seed] storefront ready", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
