# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses batch tags
(`batch/<batch_id>`) rather than semantic version releases until v1.0.

## [Unreleased]

### ui-phase-1-shell — hub shell

- Interactive level map (`/map`): SVG render of all 541 nodes from `map.generated.json` with
  pan/drag, wheel-zoom (0.35–2.5, around pointer), viewport culling, tier-coloured hex nodes,
  solved/available/locked states, keyboard navigation (arrows/Enter/±/0), an `aria-live` focus
  announcer, and a "Text map" accessible tree of real links.
- Lab detail pages (`/lab/[category]/[slug]`, all 541 statically exported): real Scenario/Objective/
  Getting-started from the catalog, free progressive hints (native `<details>`), Playable/Roadmap
  badge, and a flag-submit form.
- `labctl-client.ts`: WebSocket client for the local daemon with automatic static-mode fallback
  (1.5s connect timeout); flag form verifies live when the daemon answers, else stores locally.
- Global ⌘K command palette (native `<dialog>`, focus-trapped) over all labs + pages, fed by a
  generated `hub/public/labs-index.json`.
- No new runtime dependencies (native `<dialog>`/`<details>`, custom SVG); matrix theme + a11y throughout.
- Closes NTH-6 (build-catalog docstring); CI hub-build now also generates the map.

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
