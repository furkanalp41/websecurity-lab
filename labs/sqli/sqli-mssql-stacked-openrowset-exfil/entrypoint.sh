#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

python - <<PY > "$FLAG_PATH"
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-mssql-stacked-openrowset-exfil", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Seed MSSQL: create the inventory database, tables, sample data,
# and plant the per-container secret file that OPENROWSET BULK will read.
python /opt/app/seed.py

# Drop the raw secret so an app-side read cannot re-derive other flags.
unset LAB_USER_SECRET

exec gunicorn --chdir /opt/app --bind 0.0.0.0:8080 --workers 2 --timeout 30 app:app
