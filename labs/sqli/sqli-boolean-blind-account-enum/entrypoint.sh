#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"
python - <<PY > "$FLAG_PATH"
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-boolean-blind-account-enum", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true
unset LAB_USER_SECRET
python /opt/app/seed.py
exec uvicorn app:app --app-dir /opt/app --host 0.0.0.0 --port 8080 --workers 2
