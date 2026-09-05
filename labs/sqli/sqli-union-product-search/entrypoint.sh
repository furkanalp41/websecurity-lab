#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"
python - <<PY > "$FLAG_PATH"
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-union-product-search", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true
# The flag is now on the tmpfs. Drop the secret so an in-container read of the
# process environment cannot re-derive it.
unset LAB_USER_SECRET
# Create + seed the store (waits for MySQL; db is already healthy via depends_on).
python /opt/app/seed.py
exec gunicorn --chdir /opt/app --bind 0.0.0.0:8080 --workers 2 --timeout 30 app:app
