#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

python - <<'PY' > /tmp/lab-secrets.env
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
flag = "FLAG{%s}" % hmac.new(s, b"v1|csp-base-uri-relative-script-hijack", hashlib.sha256).hexdigest()
sess = hmac.new(s, b"admin-session|csp-base-uri-relative-script-hijack", hashlib.sha256).hexdigest()[:32]
print("FLAG=%s" % flag)
print("ADMIN_SESSION=%s" % sess)
PY
. /tmp/lab-secrets.env
printf '%s' "$FLAG" > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true
export ADMIN_SESSION
rm -f /tmp/lab-secrets.env
unset LAB_USER_SECRET
exec gunicorn --chdir /opt/app --bind 0.0.0.0:8080 --workers 1 --threads 4 --timeout 30 app:app
