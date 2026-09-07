# Track charter — SQL Injection (`sqli`)

25 labs in `data/catalog.json`. The track walks the canonical SQLi arc — from
breaking a string literal, through the injection _contexts_ learners routinely
miss (ORDER BY, cookies, headers), into blind extraction and second-order flows,
and on to WAF bypass, ORM/NoSQL variants, and OOB/stacked-query escalation.

Flag contract for every lab: `FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") }`,
written at container start by `entrypoint.sh` and gated behind the intended vuln.

## Implemented

### batch/arch-000

| slug                      | tier       | sub-class                                  |
| ------------------------- | ---------- | ------------------------------------------ |
| `sqli-login-bypass-basic` | apprentice | tautology login bypass (Apache+PHP+SQLite) |

### batch/track-sqli-a (this batch — 5 labs)

| slug                              | tier         | sub-class                                                        | stack                |
| --------------------------------- | ------------ | ---------------------------------------------------------------- | -------------------- |
| `sqli-order-by-numeric`           | apprentice   | ORDER BY / unquoted-numeric context + error oracle               | Flask + PostgreSQL   |
| `sqli-union-product-search`       | apprentice   | UNION-based extraction + verbose-error recon                     | Flask + MySQL        |
| `sqli-cookie-tracking-id`         | apprentice   | injection outside the query string (cookie) + SQLite UNION       | Go + SQLite          |
| `sqli-boolean-blind-account-enum` | practitioner | boolean-blind extraction from a response-header oracle           | FastAPI + PostgreSQL |
| `sqli-second-order-registration`  | practitioner | second-order (stored payload re-spliced in a different codepath) | Django + PostgreSQL  |

Every batch-`a` lab: non-root app + non-root DB service (hardened per
`scripts/check-posture.sh`: `read_only`, `cap_drop: ALL`, `no-new-privileges`,
pids/mem limits, loopback-only published port), intended exploit lands the flag in
under one second locally, `checker.sh` green.

### batch/track-sqli-b (this batch — 6 labs)

| slug                                       | tier         | sub-class                                                              | stack              |
| ------------------------------------------ | ------------ | ---------------------------------------------------------------------- | ------------------ |
| `sqli-error-based-extractvalue`            | apprentice   | error-based extraction via `EXTRACTVALUE`/`UPDATEXML` (XPATH errors)   | Flask + MySQL      |
| `sqli-time-blind-mysql-sleep`              | practitioner | time-based blind in an `INSERT` context (`IF(...,SLEEP(),0)` subquery) | Flask + MySQL      |
| `sqli-header-user-agent-analytics`         | practitioner | stored / second-order injection through the `User-Agent` header        | Flask + MySQL      |
| `sqli-limit-offset-postgres`               | practitioner | injection in the `LIMIT`/`OFFSET` position (scalar-subquery oracle)    | Flask + PostgreSQL |
| `sqli-waf-bypass-versioned-comments-mysql` | practitioner | keyword-blocklist WAF bypass via MySQL versioned comments `/*!...*/`   | Flask + MySQL      |
| `sqli-waf-bypass-whitespace-tabs`          | practitioner | whitespace-stripping WAF bypass (space-free payloads: `/**/`, `%0a`)   | Flask + MySQL      |

Same hardening bar as batch-`a` (non-root app + non-root DB, `read_only`,
`cap_drop: ALL`, `no-new-privileges`, pids/mem limits, loopback-only port);
each intended exploit lands the flag in well under 60 s (time-blind ~15 s,
the rest sub-second), `checker.sh` green, both Trivy gates green, image < 300 MB.

**Documented catalog deviations (see each `SOLUTION.md`):**

- `sqli-time-blind-mysql-sleep`: `secrets.beacon_token` is 16 hex chars (not the
  catalog's aspirational 40) so the intended time-based extraction completes within
  the platform's <60 s exploit gate at the same one-request-per-bit cadence.
- `sqli-limit-offset-postgres`: uses a scalar-subquery **error oracle** in the
  integer `OFFSET` position instead of a post-`LIMIT` `UNION` — Postgres grammar
  does not allow `UNION` to follow `LIMIT`, which the catalog note itself flags.
- The two WAF labs implement the filter **in-app** (a CRS-style keyword regex; a
  whitespace-stripping normaliser) rather than a separate proxy tier, keeping the
  lab to one hardened app container while teaching the identical bypass primitive.

### batch/track-sqli-c (this batch — 6 labs, native stacks)

| slug                               | tier         | sub-class                                                         | stack                           |
| ---------------------------------- | ------------ | ----------------------------------------------------------------- | ------------------------------- |
| `sqli-json-body-prisma-raw`        | practitioner | raw `$queryRawUnsafe` from a JSON body value + UNION              | Node/Fastify/Prisma + Postgres  |
| `sqli-mongo-operator-login-bypass` | practitioner | NoSQL operator injection (`$ne` bypass, `$regex` blind) — CWE-943 | Node/Express/mongoose + MongoDB |
| `sqli-couchdb-mango-selector`      | practitioner | CouchDB Mango `_find` selector access-control bypass — CWE-943    | FastAPI + CouchDB               |
| `sqli-django-extra-orm`            | expert       | Django `.extra()` raw-SQL escape hatch + UNION on `auth_user`     | Django + PostgreSQL             |
| `sqli-rails-active-record-hash`    | expert       | `Arel.sql` ORDER BY injection, ordering-oracle blind extraction   | Rails 7.2/Puma + PostgreSQL     |
| `sqli-graphql-batch-prisma-raw`    | expert       | batched-alias boolean-blind → Prisma `$queryRawUnsafe`            | Apollo Server/Prisma + Postgres |

The Hybrid "diversity" batch: each lab is built in the stack the catalog specifies
(the six now match `data/catalog.json`, enforced by the build-catalog drift-lint).
Same hardening bar as before on BOTH app and DB; exploit lands the flag in well
under 60 s; both Trivy gates green; image < 300 MB. New non-root DB/runtime patterns
(MongoDB uid 999 + bash `/dev/tcp` healthcheck; CouchDB uid 5984 + per-path tmpfs;
Node-alpine multi-stage with the bundled npm stripped from the runtime; Ruby-slim
with `pg` compiled from source and the stale default `resolv` gemspec dropped) are
documented in each lab's `SOLUTION.md` and the `CHANGELOG`.

### batch/track-sqli-d-copy-program (this batch — 1 lab, first RCE lab)

- `sqli-postgres-copy-program-rce-chain` (**elite**) — the first **SQLi-to-RCE** lab. FastAPI + asyncpg
  metrics service connected to PostgreSQL 16 **as a superuser**; a stacked-query sink (`.execute`, simple
  protocol) runs `CREATE TABLE loot; COPY loot FROM PROGRAM 'cat /labflag/flag.txt'` for command execution
  inside the Postgres container, and a visible sink (`.fetch`, UNION) reads the output back. The flag is
  planted on the Postgres filesystem (superuser `COPY TO`, derived app-side; the secret never reaches
  Postgres), so only RCE recovers it. **Stays `risk: low`**: `COPY PROGRAM` needs no added caps, so
  `cap_drop: ALL` + read-only rootfs are kept, and the Postgres container is put on an `internal: true`
  **no-egress** network (no default route — verified). No new CI infra needed. app+db posture green, both
  Trivy gates green (fastapi 0.141 / starlette 1.6), 157 MB, exploit <1 s.

### batch/track-sqli-d-layerslider (this batch — 1 lab, first PHP/WAF lab)

- `sqli-layerslider-unauth-time-blind` (**elite**) — unauthenticated time-based blind SQLi through a
  WordPress-style plugin AJAX action (`admin-ajax.php?action=ls_get_popup_markup`), abstracting
  **CVE-2024-2879 (LayerSlider)**. Teaches the `wpdb::prepare()` concatenation footgun (a query built by
  string interpolation with no `%d` placeholder is not parameterised), reading a secret through a pure
  timing oracle (response body/status never vary), and **bypassing a CRS-baseline SQLi filter** with
  inline-comment obfuscation (`SLEEP/**/(`) + hex string literals (`0x61646d696e`) under a per-IP rate
  limiter. First lab in the track on the **PHP 8.2 / Apache 2.4 / MariaDB 11.4** stack (Alpine, 26 MB),
  with an app-level WAF homage and a non-root app + non-root DB. Intended exploit lands the flag in
  ~15–25 s; posture gate, both Trivy gates, `<300 MB`, and no-baked-flag all green. `user_pass` is a
  16-hex token (documented deviation) so the rate-limited extraction clears the `<60 s` gate.

## Learning-objective coverage (batch-a)

- ORDER BY / non-string injection contexts and CAST/error oracles — `sqli-order-by-numeric`
- Column-count enumeration + UNION SELECT + `information_schema` — `sqli-union-product-search`
- Injection surfaces beyond the URL (cookies) + SQLite metadata — `sqli-cookie-tracking-id`
- Building a boolean oracle from a subtle response difference + binary-search exfil — `sqli-boolean-blind-account-enum`
- Second-order data flow (source ≠ sink, across endpoints/time) — `sqli-second-order-registration`

## Scheduled (future batches, Linux-feasible)

**Implemented: 20/25.** The remaining 5 catalog entries are the infeasible-as-
specified labs in the next section (Windows-container MSSQL/Fortinet/MoVEit and
heavy-tier Oracle/Elasticsearch). `sqli-postgres-copy-program-rce-chain` shipped as
a `risk: low` egress-dropped RCE lab (COPY FROM PROGRAM needs no added caps). Pending the
operator's charter decision (abstract onto a Linux stack, grant a heavy
resource-tier, or drop).

## Coverage gaps — infeasible as specified (needs an AUDITOR/operator charter decision)

These catalog labs cannot run under the platform's constraints (Linux Docker host,
`mem_limit: 512m`, `<300 MB` image, `<60 s` exploit) and are **deferred pending a
re-platform decision** (abstract the vuln class onto a Linux-runnable stack):

- `sqli-mssql-stacked-xp-cmdshell` — specifies **Windows Nano Server** (Windows container; cannot run on a Linux host).
- `sqli-fortinet-ems-fctuid-rce` — **Windows Server Core** + MSSQL (Windows container); also a §13 CVE-homage.
- `sqli-moveit-header-auth-bypass-chain` — ASP.NET + MSSQL Server (heavy; >512m); §13 CVE-homage.
- `sqli-oob-dns-oracle-utlhttp` — **Oracle 21c XE** (~2–4 GB image, 60–120 s start; blows size/time gates).
- `sqli-elasticsearch-dsl-painless` — **Elasticsearch 8.15** (requires >512 MB RAM; won't start under the mem cap).

Proposed resolution: re-platform the MSSQL/Oracle/Elasticsearch labs onto Linux-runnable
equivalents that teach the same primitive (stacked queries / OOB exfil / DSL injection),
and treat the RCE-chain lab as `risk: elevated`. Awaiting AUDITOR + operator sign-off.
