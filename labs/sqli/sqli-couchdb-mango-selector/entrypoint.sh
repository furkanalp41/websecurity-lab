#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# Per-container flag derived from the per-user secret; never baked into a layer.
python - <<'PY' > "$FLAG_PATH"
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-couchdb-mango-selector", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Template hardening: drop the secret from the process environment before the app
# starts, so an in-container read (/proc/self/environ) cannot recover it. The flag
# is only revealed by /solve once the intended selector-injection is solved.
unset LAB_USER_SECRET

# depends_on waits for the DB healthcheck; seed.py additionally guards the startup
# race and is idempotent (safe on app restarts). Runs AFTER the flag step.
python /opt/app/seed.py

exec uvicorn app:app --app-dir /opt/app --host 0.0.0.0 --port 8080 --workers 2
