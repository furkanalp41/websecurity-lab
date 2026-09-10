# SPDX-License-Identifier: MIT
"""Wait for Oracle, then set up schema + network ACL + per-container secret.

Runs entirely from the app container as APP_USER + SYS (via SYSDBA connect).
python-oracledb thin mode = pure Python, no Instant Client needed.

Two SYS-side operations required (both empirically verified 2026-09-10):
  1. GRANT EXECUTE ON UTL_HTTP TO REPORTAPP  (gvenzl's APP_USER may not have it)
  2. APPEND_HOST_ACE to permit REPORTAPP to reach 'oob' port 9000 — without this
     UTL_HTTP.REQUEST fails with ORA-29273 (network ACL denial masked as a
     generic HTTP failure). Modern DBMS_NETWORK_ACL_ADMIN API.

The per-container `oracle_secret` (32 lowercase hex chars) is derived app-side
from LAB_USER_SECRET; the raw secret NEVER reaches Oracle.
"""
import hashlib
import hmac
import os
import time

import oracledb

SYS_PASSWORD = os.environ.get("ORACLE_PASSWORD", "")
APP_USER = os.environ.get("APP_USER", "reportapp")
APP_PASSWORD = os.environ.get("APP_USER_PASSWORD", "")
DB_HOST = os.environ.get("DB_HOST", "db")
DB_PORT = int(os.environ.get("DB_PORT", "1521"))
DB_SERVICE = os.environ.get("DB_SERVICE", "XEPDB1")
OOB_HOST = os.environ.get("OOB_HOST", "oob")
OOB_PORT = int(os.environ.get("OOB_PORT", "9000"))


def connect_sys(service: str) -> oracledb.Connection:
    for attempt in range(120):
        try:
            return oracledb.connect(
                user="sys", password=SYS_PASSWORD,
                dsn=f"{DB_HOST}:{DB_PORT}/{service}",
                mode=oracledb.AUTH_MODE_SYSDBA,
            )
        except Exception:  # noqa: BLE001 -- retry until PDB open
            if attempt == 0:
                print(f"[seed] waiting for oracle ({service})...", flush=True)
            time.sleep(2)
    raise SystemExit(f"[seed] oracle ({service}) never became ready")


def connect_app() -> oracledb.Connection:
    return oracledb.connect(
        user=APP_USER, password=APP_PASSWORD,
        dsn=f"{DB_HOST}:{DB_PORT}/{DB_SERVICE}",
    )


def main() -> None:
    # Network ACLs are per-PDB — connect as SYS to XEPDB1 (not the CDB root).
    sys_conn = connect_sys(DB_SERVICE)
    try:
        with sys_conn.cursor() as cur:
            cur.execute("GRANT EXECUTE ON UTL_HTTP TO " + APP_USER)
            cur.execute(
                "BEGIN "
                "  DBMS_NETWORK_ACL_ADMIN.APPEND_HOST_ACE("
                "    host       => :host,"
                "    lower_port => :lo, upper_port => :hi,"
                "    ace        => xs$ace_type("
                "      privilege_list => xs$name_list('http'),"
                "      principal_name => :princ,"
                "      principal_type => xs_acl.ptype_db));"
                "END;",
                host=OOB_HOST, lo=OOB_PORT, hi=OOB_PORT, princ=APP_USER.upper(),
            )
        sys_conn.commit()
    finally:
        sys_conn.close()

    app_conn = connect_app()
    try:
        with app_conn.cursor() as cur:
            for stmt in (
                "BEGIN EXECUTE IMMEDIATE 'DROP TABLE reports'; EXCEPTION WHEN OTHERS THEN NULL; END;",
                "BEGIN EXECUTE IMMEDIATE 'DROP TABLE secrets'; EXCEPTION WHEN OTHERS THEN NULL; END;",
                "CREATE TABLE reports (id NUMBER PRIMARY KEY, title VARCHAR2(200), region VARCHAR2(60))",
                "CREATE TABLE secrets (id NUMBER PRIMARY KEY, oracle_secret VARCHAR2(64))",
            ):
                cur.execute(stmt)
            for r in [
                (1, "Q1 revenue by region", "APAC"),
                (2, "Fraud incidents by month", "EMEA"),
                (3, "SLA breaches", "AMER"),
            ]:
                cur.execute("INSERT INTO reports VALUES (:1, :2, :3)", r)

            raw = os.environ.get("LAB_USER_SECRET", "")
            if not raw:
                raise SystemExit("[seed] LAB_USER_SECRET not available at seed time")
            secret = hmac.new(
                raw.encode(), b"oracle-secret|sqli-oob-dns-oracle-utlhttp",
                hashlib.sha256,
            ).hexdigest()[:32]
            cur.execute("INSERT INTO secrets VALUES (1, :1)", [secret])
        app_conn.commit()
    finally:
        app_conn.close()

    print(f"[seed] oracle ready — reports+secrets seeded, ACL for {OOB_HOST}:{OOB_PORT} granted to {APP_USER.upper()}",
          flush=True)


if __name__ == "__main__":
    main()
