#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# Per-container flag (HMAC over the slug), the admin session cookie that gates the
# review page, and the admin CSRF token embedded in the review form. The CSRF
# token is the secret the formaction attack must steal; /solve returns the flag
# when the exfiltrated token matches it.
python - <<'PY' > /tmp/lab-secrets.env
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
flag = "FLAG{%s}" % hmac.new(s, b"v1|formaction-xss-button-injection", hashlib.sha256).hexdigest()
sess = hmac.new(s, b"admin-session|formaction-xss-button-injection", hashlib.sha256).hexdigest()[:32]
csrf = hmac.new(s, b"admin-csrf|formaction-xss-button-injection", hashlib.sha256).hexdigest()[:32]
print("FLAG=%s" % flag)
print("ADMIN_SESSION=%s" % sess)
print("ADMIN_CSRF=%s" % csrf)
PY
. /tmp/lab-secrets.env
printf '%s' "$FLAG" > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true
export ADMIN_SESSION ADMIN_CSRF
rm -f /tmp/lab-secrets.env

# Drop the raw lab secret so an app-side read cannot re-derive other instances.
unset LAB_USER_SECRET

# Single worker: the draft store and admin session/CSRF live in-process.
exec gunicorn --chdir /opt/app --bind 0.0.0.0:8080 --workers 1 --threads 4 --timeout 30 app:app
