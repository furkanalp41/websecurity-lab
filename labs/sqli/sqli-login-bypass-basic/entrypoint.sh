#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"

mkdir -p "$(dirname "$FLAG_PATH")"
# Per-container flag derived from the per-user secret; never baked into a layer.
php -r 'echo "FLAG{".hash_hmac("sha256","v1|sqli-login-bypass-basic",getenv("LAB_USER_SECRET"))."}\n";' > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Seed the SQLite database (root gets a random, unknown password).
php /opt/lab/init_db.php

exec httpd -D FOREGROUND
