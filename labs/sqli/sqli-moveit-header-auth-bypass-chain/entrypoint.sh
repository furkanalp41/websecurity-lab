#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
CONF_DIR="${CONF_DIR:-/var/lib/lab/confidential}"
mkdir -p "$(dirname "$FLAG_PATH")" "$CONF_DIR"

# Per-container flag (returned by /solve on a correct hash).
python - <<PY > "$FLAG_PATH"
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
print("FLAG{%s}" % hmac.new(s, b"v1|sqli-moveit-header-auth-bypass-chain", hashlib.sha256).hexdigest())
PY
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Per-container confidential file. Its bytes are derived from the secret so its
# SHA-256 is unique to THIS instance — a learner must actually download it (via
# the forged session) to compute the right hash; a hash from another instance
# will not validate. The file never contains the flag itself.
python - <<PY
import hashlib, hmac, os
s = os.environ["LAB_USER_SECRET"].encode()
blob = hmac.new(s, b"confidential-blob|sqli-moveit-header-auth-bypass-chain", hashlib.sha256).digest()
# 4 KiB of deterministic-but-per-container pseudo-random bytes.
data = b""
ctr = 0
while len(data) < 4096:
    data += hmac.new(s, b"blob-%d" % ctr, hashlib.sha256).digest()
    ctr += 1
open(os.path.join(os.environ.get("CONF_DIR", "/var/lib/lab/confidential"), "flag.bin"), "wb").write(data[:4096])
PY

# Seed the audit/session/user schema (waits for Postgres; db healthy via depends_on).
python /opt/app/seed.py

# Drop the secret so an app-side read cannot re-derive other instances' flags.
unset LAB_USER_SECRET

exec gunicorn --chdir /opt/app --bind 0.0.0.0:8080 --workers 2 --timeout 30 app:app
