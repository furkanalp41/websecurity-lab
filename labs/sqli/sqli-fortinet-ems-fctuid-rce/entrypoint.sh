#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# Per-container flag (returned by /solve on a correct submission).
python - <<PY > "$FLAG_PATH"
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-fortinet-ems-fctuid-rce", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Seed the audit schema AND plant the flag on the Postgres container filesystem
# via a superuser server-side COPY ... TO write. Recoverable only through COPY
# ... FROM/TO PROGRAM command execution — never a plain SQL SELECT.
python /opt/app/seed.py

# Drop the secret before uvicorn/gunicorn so an app-side read cannot re-derive
# other instances' flags. Postgres never received the secret at all.
unset LAB_USER_SECRET

exec gunicorn --chdir /opt/app --bind 0.0.0.0:8080 --workers 2 --timeout 30 app:app
