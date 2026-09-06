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
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-django-extra-orm", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Template hardening: drop the secret from the process environment before the app
# starts, so an in-container read (/proc/self/environ) cannot recover it. The flag
# is only revealed by /solve once the intended .extra() injection is solved.
unset LAB_USER_SECRET

cd /opt/app

# depends_on waits for the DB healthcheck, but guard the startup race explicitly.
python - <<'PY'
import os, sys, time
import psycopg

dsn = "host=%s port=%s dbname=%s user=%s password=%s" % (
    os.environ.get("DB_HOST", "db"),
    os.environ.get("DB_PORT", "5432"),
    os.environ.get("DB_NAME", "app_db"),
    os.environ.get("DB_USER", "appuser"),
    os.environ.get("DB_PASSWORD", ""),
)
for attempt in range(60):
    try:
        psycopg.connect(dsn).close()
        break
    except Exception:
        if attempt == 0:
            print("[entrypoint] waiting for database...", flush=True)
        time.sleep(1)
else:
    sys.exit("[entrypoint] database never became ready")
PY

# Build the schema, then seed the products and the per-container superuser (whose
# random pbkdf2_sha256$ hash is the objective). AFTER the flag step, per contract.
python manage.py migrate --noinput
python manage.py seed_lab

exec gunicorn --chdir /opt/app --bind 0.0.0.0:8080 --workers 2 --timeout 30 project.wsgi:application
