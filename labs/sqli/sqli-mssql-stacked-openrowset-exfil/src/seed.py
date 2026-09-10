# SPDX-License-Identifier: MIT
"""Seed the MSSQL inventory database.

Run by entrypoint.sh BEFORE gunicorn starts. Connects as SA (sysadmin) to:
  1. Create the `inventory` database with assets, notices, and secrets tables.
  2. Insert sample asset data and a welcome notice.
  3. Plant a per-container mssql_secret (derived from LAB_USER_SECRET) in the
     secrets table. No endpoint ever exposes this table — the student must
     exfiltrate it via stacked-query injection.

Ad Hoc Distributed Queries (OPENROWSET) is deliberately left DISABLED. The
student may enable it via sp_configure as an alternative exfil vector (file
read from the DB filesystem), but the primary path is stacked INSERT from
secrets into the notices table.
"""
import hashlib
import hmac
import os
import time

import pyodbc

DB_HOST = os.environ.get("DB_HOST", "db")
DB_PORT = os.environ.get("DB_PORT", "1433")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
LAB_USER_SECRET = os.environ["LAB_USER_SECRET"]

CONN_STR = (
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
    f"SERVER={DB_HOST},{DB_PORT};"
    f"UID=sa;PWD={DB_PASSWORD};"
    f"TrustServerCertificate=yes;"
    f"Encrypt=no;"
)

SECRET = hmac.new(
    LAB_USER_SECRET.encode(),
    b"mssql-secret|sqli-mssql-stacked-openrowset-exfil",
    hashlib.sha256,
).hexdigest()[:32]


def wait_for_mssql(retries: int = 30, delay: float = 2.0) -> pyodbc.Connection:
    for i in range(retries):
        try:
            conn = pyodbc.connect(CONN_STR, autocommit=True)
            conn.execute("SELECT 1")
            return conn
        except pyodbc.Error:
            if i == retries - 1:
                raise
            time.sleep(delay)
    raise RuntimeError("unreachable")


def seed() -> None:
    conn = wait_for_mssql()

    conn.execute("IF DB_ID('inventory') IS NULL CREATE DATABASE inventory")
    conn.execute("USE inventory")

    conn.execute("""
        IF OBJECT_ID('assets', 'U') IS NULL
        CREATE TABLE assets (
            id INT IDENTITY PRIMARY KEY,
            name NVARCHAR(200) NOT NULL,
            category NVARCHAR(100) NOT NULL,
            serial_no NVARCHAR(50),
            assigned_to NVARCHAR(100)
        )
    """)

    conn.execute("""
        IF OBJECT_ID('notices', 'U') IS NULL
        CREATE TABLE notices (
            id INT IDENTITY PRIMARY KEY,
            title NVARCHAR(200) NOT NULL,
            body NVARCHAR(MAX),
            posted_at DATETIME DEFAULT GETDATE()
        )
    """)

    conn.execute("""
        IF OBJECT_ID('secrets', 'U') IS NULL
        CREATE TABLE secrets (
            id INT PRIMARY KEY,
            mssql_secret NVARCHAR(32) NOT NULL
        )
    """)

    row = conn.execute("SELECT COUNT(*) FROM assets").fetchone()
    if row[0] == 0:
        assets = [
            ("ThinkPad X1 Carbon", "Laptops", "SN-LP-0401", "alice"),
            ("ThinkPad T14s", "Laptops", "SN-LP-0402", "bob"),
            ("Dell U2723QE", "Monitors", "SN-MN-0501", "alice"),
            ("Dell U2722D", "Monitors", "SN-MN-0502", "charlie"),
            ("Logitech MX Keys", "Peripherals", "SN-KB-0601", "alice"),
            ("Logitech MX Master 3S", "Peripherals", "SN-MS-0602", "bob"),
            ("Cisco Catalyst 9200", "Network", "SN-NW-0701", None),
            ("Ubiquiti U6 Pro", "Network", "SN-NW-0702", None),
            ("HP LaserJet Pro", "Printers", "SN-PR-0801", None),
            ("APC Smart-UPS 1500", "Power", "SN-PW-0901", None),
        ]
        for name, cat, sn, assigned in assets:
            conn.execute(
                "INSERT INTO assets(name, category, serial_no, assigned_to) "
                "VALUES (?, ?, ?, ?)",
                name, cat, sn, assigned,
            )

    row = conn.execute("SELECT COUNT(*) FROM notices").fetchone()
    if row[0] == 0:
        conn.execute(
            "INSERT INTO notices(title, body) VALUES (?, ?)",
            "System launched",
            "The asset inventory system is now online.",
        )

    row = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()
    if row[0] == 0:
        conn.execute(
            "INSERT INTO secrets(id, mssql_secret) VALUES (1, ?)",
            SECRET,
        )

    conn.close()
    print("[seed] MSSQL inventory database seeded.")


if __name__ == "__main__":
    seed()
