#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
export FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# Per-container flag derived from the per-user secret; never baked into a layer.
# FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") }. Computed with Ruby's OpenSSL.
ruby -ropenssl -e 'File.write(ENV["FLAG_PATH"], "FLAG{" + OpenSSL::HMAC.hexdigest("SHA256", ENV["LAB_USER_SECRET"], "v1|sqli-rails-active-record-hash") + "}\n")'
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Template hardening: drop the secret from the process environment before the app
# starts, so an in-container read (/proc/self/environ) cannot recover it. The flag
# is only revealed by /solve once the intended ORDER BY injection is solved.
unset LAB_USER_SECRET

cd /opt/app

# depends_on waits for the DB healthcheck, but guard the startup race explicitly:
# create the schema and seed the per-container secret (idempotent), retrying until
# the database accepts connections.
# Boot the app environment explicitly and run the seed. NB: `rails runner` does
# not work in this minimal component-based app (no bin/rails / app autodetect) —
# it prints the `rails new` help and exits 0, which would silently skip seeding
# and leave the tables missing. Loading config/environment then the seed script
# runs the DDL in a real app context, and fails (non-zero) until the DB is up so
# the retry loop is honest.
n=0
until bundle exec ruby -e 'require "/opt/app/config/environment"; load "/opt/app/db/seed_lab.rb"'; do
  n=$((n + 1))
  if [ "$n" -ge 30 ]; then
    echo "[entrypoint] database never became ready / seed failed" >&2
    exit 1
  fi
  [ "$n" -eq 1 ] && echo "[entrypoint] waiting for database..."
  sleep 2
done

exec bundle exec puma -C /opt/app/config/puma.rb
