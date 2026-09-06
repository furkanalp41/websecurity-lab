# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses batch tags
(`batch/<batch_id>`) rather than semantic version releases until v1.0.

## [Unreleased]

### chore-sqli-c-docs — docs/metadata polish for track-sqli-c (AUDITOR BL-1..BL-8)

- **BL-1**: `sqli-json-body-prisma-raw` and `sqli-rails-active-record-hash` SOLUTION.md now list ≥3 distinct payload vectors each.
- **BL-2**: all six track-sqli-c SOLUTION.md carry an explicit **OWASP / CWE / CVE** line.
- **BL-3**: `sqli-json-body-prisma-raw` catalog prose corrected (real `SELECT id, title, status` column list; text, not jsonb, columns).
- **BL-4**: `sqli-couchdb-mango-selector` meta `inspired_by` no longer cites the unrelated CVE-2022-24706 (Erlang-dist RCE).
- **BL-5**: `sqli-django-extra-orm` bumped Django 5.1.14 (security-EOL) → **5.2.17 LTS** (rebuilt + re-verified, Trivy green).
- **BL-6**: `sqli-rails-active-record-hash` version drift fixed (`load_defaults`/README/Gemfile 7.1 → 7.2), stale `rails runner` and nokogiri comments corrected, README time aligned to meta (45 min), dropped `permit(:category)` for a non-existent column.
- **BL-7**: `sqli-graphql-batch-prisma-raw` SOLUTION backticks repaired, README no longer spells out the breakout (deferred to hints), and the non-existent "resolver-level rate limit" claim removed from the objective/SOLUTION.
- **BL-8**: `sqli-mongo-operator-login-bypass` and `sqli-django-extra-orm` `exposed_service.http_path` now point at the GET landing (`/`) instead of a POST-only route.
- Docs/metadata/version-currency only; the two rebuilt labs (django, rails) re-verified green (posture, exploit, checker, both Trivy gates, < 300 MB).

### track-sqli-c — native-stack SQLi/NoSQL labs 13–18 (6)

- Six new labs built in their **native stacks** (the Hybrid "diversity" batch), each with a hardened
  non-root app AND non-root database service, intended exploit landing the flag in under 60 s, a passing
  multi-container posture gate, both Trivy gates (library + OS) green, and image < 300 MB:
  `sqli-json-body-prisma-raw` (Node/Fastify/Prisma `$queryRawUnsafe` via a JSON body value, Postgres),
  `sqli-mongo-operator-login-bypass` (NoSQL `$ne` auth bypass + `$regex` blind extraction, Node/Express/mongoose/MongoDB, CWE-943),
  `sqli-couchdb-mango-selector` (Mango `_find` selector access-control bypass, FastAPI/CouchDB, CWE-943),
  `sqli-django-extra-orm` (`.extra()` raw-SQL UNION to read `auth_user`, Django/Postgres),
  `sqli-rails-active-record-hash` (`Arel.sql` ORDER BY ordering-oracle blind extraction, Rails 7.2/Puma/Postgres),
  `sqli-graphql-batch-prisma-raw` (batched-alias boolean-blind feeding Prisma `$queryRawUnsafe`, Apollo Server/Prisma/Postgres).
- New hardened non-root DB / runtime patterns established for the platform:
  - **MongoDB 7** — uid 999, tmpfs `/data/db`, `--wiredTigerCacheSizeGB 0.25`, and a bash `/dev/tcp` healthcheck
    (mongosh as a healthcheck spawned a ~150 MB Node process each interval and OOM-killed mongod under `mem_limit`).
  - **CouchDB 3.4** — uid 5984, tmpfs for every writable path (`/opt/couchdb/data`, `/opt/couchdb/etc/local.d`).
  - **Node 20-alpine** — multi-stage; Prisma musl query-engine + `apk add openssl` (else Prisma loads a missing
    1.1.x engine); the base image's bundled **npm is stripped from the runtime** (its deep dep tree — tar/pacote/
    sigstore/minimatch/… — carries fixed HIGH CVEs the library gate blocks, none reachable in a `node`-only runtime).
  - **Ruby 3.3-slim** — multi-stage; `pg` compiled from source (`BUNDLE_FORCE_RUBY_PLATFORM`) so it links the system
    libpq; stale default `resolv` gemspec dropped so the patched bundled gem is what the scanner sees.
- 18/25 SQLi labs implemented — **all Linux-feasible SQLi labs are now done**. `data/catalog.json` tech_stack
  reconciled to the shipped stacks for the six (drift-lint green).

### chore-catalog-reconcile — catalog honesty + drift guardrail

- Reconciled `data/catalog.json` `tech_stack` for all 12 implemented labs to match each
  lab's shipped `meta.json` (track-a stays diverse as built; the 6 track-b labs are Flask),
  per the operator's Hybrid re-platform ruling (future feasible labs default to Flask +
  MySQL/Postgres; stack diversity revisited later for select flagship tracks).
- Fixed `sqli-limit-offset-postgres`'s catalog description/objective, which described a
  post-`LIMIT` `UNION` (forbidden in Postgres) rather than the shipped scalar-subquery error oracle.
- `scripts/build-catalog.ts`: new gate — an implemented lab whose catalog `tech_stack` differs
  from its `meta.json` now fails the build (exact array equality), so the two cannot silently
  drift again. Unbuilt catalog entries keep their aspirational stack freely. Resolves the
  track-a/-b `tech_stack`-drift follow-up.

### track-sqli-b — SQLi labs 7–12 (6)

- Six new SQLi labs extending the track into new injection techniques, contexts, and surfaces —
  each with a hardened non-root app AND non-root database service, exploit landing the flag in
  well under 60 s, passing multi-container posture gate, and both Trivy gates (library + OS) green:
  `sqli-error-based-extractvalue` (EXTRACTVALUE/UPDATEXML XPATH error exfil with 32-char
  truncation chunking, MySQL), `sqli-time-blind-mysql-sleep` (time-based blind in an INSERT
  context via `IF(...,SLEEP(),0)` subquery, MySQL — threaded exploit, ~15 s),
  `sqli-header-user-agent-analytics` (stored/second-order injection through the `User-Agent`
  header, re-spliced on the admin read path, MySQL), `sqli-limit-offset-postgres` (injection in
  the `LIMIT/OFFSET` position via a scalar-subquery error oracle, Postgres),
  `sqli-waf-bypass-versioned-comments-mysql` (MySQL `/*!50000...*/` versioned-comment keyword
  evasion, with a `/waf-log` rule-fired oracle), `sqli-waf-bypass-whitespace-tabs` (space-free
  payloads via `/**/` and newline separators against a whitespace-stripping filter, with a
  `/debug` byte-echo endpoint).
- Deliberate deviations from `data/catalog.json`, documented in each lab's `SOLUTION.md`:
  the time-blind token is 16 hex chars (not 40) so the intended exploit fits the platform's
  <60 s exploit gate at the same 1-bit-per-request cadence; the LIMIT/OFFSET lab uses a scalar
  subquery error oracle rather than a post-`LIMIT` `UNION` (which Postgres grammar forbids).
- 12 labs implemented total (all `sqli`); catalog/map regenerate clean.

### track-sqli-a — first SQLi labs (5)

- Five new SQLi labs covering the core progression, each with a hardened non-root app AND
  non-root database service (read_only, cap_drop ALL, no-new-privileges, pids/mem limits,
  loopback-only port), exploit landing the flag in <1s, and a passing multi-container posture gate:
  `sqli-order-by-numeric` (ORDER BY error-oracle, Postgres), `sqli-union-product-search`
  (UNION, MySQL), `sqli-cookie-tracking-id` (cookie UNION, Go+SQLite),
  `sqli-boolean-blind-account-enum` (boolean-blind, FastAPI+Postgres),
  `sqli-second-order-registration` (second-order, Django+Postgres).
- `scripts/check-posture.sh` now asserts the baseline on every container in a lab (app + DB);
  CI passes all compose container ids.
- Established the hardened non-root Postgres (user 70) and MySQL (user 999) multi-service patterns.
- `packages/schema/enums.json`: added CWE-204 (Observable Response Discrepancy) and CWE-208.
- `docs/tracks/sqli.md`: track charter; defers Windows-container / Oracle / Elasticsearch labs
  as infeasible-as-specified (charter decision pending).

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
