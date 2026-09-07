#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"

mkdir -p "$(dirname "$FLAG_PATH")"
# Per-container flag derived from the per-user secret; never baked into a layer.
php -r 'echo "FLAG{".hash_hmac("sha256","v1|sqli-layerslider-unauth-time-blind",getenv("LAB_USER_SECRET"))."}\n";' > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Drop the per-user secret from the environment before Apache (and therefore any
# PHP request handler) starts, so an in-container read of /proc/self/environ
# cannot re-derive the flag. The flag now lives only on the /var/lib/lab tmpfs.
unset LAB_USER_SECRET

# Create + seed the WordPress-style schema (waits for MariaDB; the db is already
# healthy via depends_on). A RANDOM 16-hex value is written to wp_users.user_pass
# for user_login='admin' and is recoverable only through the timing oracle.
php /opt/lab/seed.php

# Prefork Apache needs a writable runtime dir for its scoreboard/pid; /run/apache2
# is a tmpfs (see compose). Run in the foreground as the non-root 'app' user.
exec httpd -D FOREGROUND
