# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses batch tags
(`batch/<batch_id>`) rather than semantic version releases until v1.0.

## [Unreleased]

### arch-000 — P0 bootstrap

- Monorepo scaffold: pnpm 9 workspace (`hub`, `labctl`, `packages/*`), Node 24 pin, TS strict base config.
- Next.js 15 App Router hub with matrix-theme shell, design tokens, code-rain, and 9 route stubs.
- `labctl` CLI skeleton (commander) + WebSocket daemon skeleton bound to `127.0.0.1:5174`
  (origin allowlist, per-install bearer token) + SQLite schema + `meta.schema.json` v1.0.0.
- `packages/schema` canonical OWASP Top 10 (2021) / API Top 10 (2023) / CWE enums.
- Sample lab `labs/sqli/sqli-login-bypass-basic` (the `labctl new-lab` template) — all seven artifact groups,
  digest-pinned Alpine+Apache+PHP+SQLite, non-root, read-only rootfs, `cap_drop: ALL`, exploit lands in <1s.
- `scripts/build-catalog.ts` (schema-validated catalog index) and `scripts/build-map.ts` (elkjs layered map).
- CI: lint + typecheck + schema-validate + hub-build + docker-lab-matrix + gitleaks + trivy + dive.
- Kickoff pack staged into `data/` and `docs/`.
