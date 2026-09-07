#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# Derive the per-container flag from the per-user secret and keep an app-local
# copy (tmpfs) purely so /solve can compare a submission. This copy lives in the
# APP container, which has no file-read/RCE bug — the challenge target is the
# Postgres container.
python - <<PY > "$FLAG_PATH"
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-postgres-copy-program-rce-chain", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Seed the metrics DB AND plant the same flag onto the POSTGRES container's
# filesystem (via a superuser COPY ... TO server-side write) so it is recoverable
# ONLY through command execution, never a plain SQL SELECT. seed.py reads the
# flag from FLAG_PATH; the raw secret is never sent to Postgres.
python /opt/app/seed.py

# Drop the secret before the server starts so an app-side read of the process
# environment cannot re-derive flags for other instances. (The Postgres container
# never received the secret at all.)
unset LAB_USER_SECRET

exec uvicorn --app-dir /opt/app app:app --host 0.0.0.0 --port 8080 --workers 2
