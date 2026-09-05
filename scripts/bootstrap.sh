#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# First-run installer: preflight, install deps, generate the catalog, build labctl.
# Idempotent — safe to re-run. Pass --with-hub to also build the static hub.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say() { printf '\033[0;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[warn]\033[0m %s\n' "$*"; }
die() { printf '\033[0;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

say "Preflight"
command -v node >/dev/null 2>&1 || die "node not found (need v24+; see .nvmrc)"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 24 ] || die "node v${NODE_MAJOR} too old; need v24+ (nvm use 24)"
command -v docker >/dev/null 2>&1 || warn "docker not found — labs will not run until Docker Engine 25+ is installed"
docker compose version >/dev/null 2>&1 || warn "docker compose v2 not found"
command -v git >/dev/null 2>&1 || die "git not found"
if ! command -v pnpm >/dev/null 2>&1; then
  say "Enabling pnpm via corepack"
  corepack enable >/dev/null 2>&1 || die "corepack enable failed; install pnpm 9 manually"
fi

say "Installing workspace dependencies (pnpm)"
if [ -f pnpm-lock.yaml ]; then
  pnpm install --frozen-lockfile || pnpm install
else
  pnpm install
fi

say "Generating catalog index"
pnpm run catalog

say "Building labctl"
pnpm --filter @websec-lab/labctl build

if [ "${1:-}" = "--with-hub" ]; then
  say "Building static hub"
  NEXT_STATIC=1 pnpm --filter hub build
fi

say "Done. Next: ./labctl serve  (or: node labctl/dist/cli.js doctor)"
