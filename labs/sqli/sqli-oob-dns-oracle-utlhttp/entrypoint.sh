#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# Per-container flag; /solve returns it on a correct secret submission.
python - <<PY > "$FLAG_PATH"
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-oob-dns-oracle-utlhttp", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Seed Oracle:
#   - as SYS: GRANT EXECUTE ON UTL_HTTP + DBMS_LOCK to REPORTAPP; create a
#     NETWORK ACL that permits REPORTAPP to make HTTP calls to the in-lab
#     collector (host=oob, port 9000). Oracle 12c+ requires this.
#   - as REPORTAPP: create the `reports` schema and insert a random
#     per-container secret into secrets.oracle_secret (derived from
#     LAB_USER_SECRET; never persisted in the app image).
python /opt/app/seed.py

# Drop the raw secret so an app-side read cannot re-derive other instances' flags
# (the Oracle DB has the DERIVED secret in a row, not the raw secret).
unset LAB_USER_SECRET

exec gunicorn --chdir /opt/app --bind 0.0.0.0:8080 --workers 2 --timeout 30 app:app
