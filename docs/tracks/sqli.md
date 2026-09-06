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

## Learning-objective coverage (batch-a)

- ORDER BY / non-string injection contexts and CAST/error oracles — `sqli-order-by-numeric`
- Column-count enumeration + UNION SELECT + `information_schema` — `sqli-union-product-search`
- Injection surfaces beyond the URL (cookies) + SQLite metadata — `sqli-cookie-tracking-id`
- Building a boolean oracle from a subtle response difference + binary-search exfil — `sqli-boolean-blind-account-enum`
- Second-order data flow (source ≠ sink, across endpoints/time) — `sqli-second-order-registration`

## Scheduled (future batches, Linux-feasible)

Remaining after track-sqli-b (each adds a new DB engine or language runtime, so
they are grouped for a later batch): `sqli-json-body-prisma-raw` (Node/Prisma),
`sqli-mongo-operator-login-bypass` (MongoDB), `sqli-couchdb-mango-selector`
(CouchDB), `sqli-django-extra-orm`, `sqli-rails-active-record-hash` (Rails),
`sqli-graphql-batch-prisma-raw`, `sqli-layerslider-unauth-time-blind` →
track-sqli-c (≤20 labs per batch).

## Coverage gaps — infeasible as specified (needs an AUDITOR/operator charter decision)

These catalog labs cannot run under the platform's constraints (Linux Docker host,
`mem_limit: 512m`, `<300 MB` image, `<60 s` exploit) and are **deferred pending a
re-platform decision** (abstract the vuln class onto a Linux-runnable stack):

- `sqli-mssql-stacked-xp-cmdshell` — specifies **Windows Nano Server** (Windows container; cannot run on a Linux host).
- `sqli-fortinet-ems-fctuid-rce` — **Windows Server Core** + MSSQL (Windows container); also a §13 CVE-homage.
- `sqli-moveit-header-auth-bypass-chain` — ASP.NET + MSSQL Server (heavy; >512m); §13 CVE-homage.
- `sqli-oob-dns-oracle-utlhttp` — **Oracle 21c XE** (~2–4 GB image, 60–120 s start; blows size/time gates).
- `sqli-elasticsearch-dsl-painless` — **Elasticsearch 8.15** (requires >512 MB RAM; won't start under the mem cap).
- `sqli-postgres-copy-program-rce-chain` — Postgres `COPY … PROGRAM` → RCE; needs the §13 offline/egress-drop + elevated-risk treatment (schedule as a `risk: elevated` lab).

Proposed resolution: re-platform the MSSQL/Oracle/Elasticsearch labs onto Linux-runnable
equivalents that teach the same primitive (stacked queries / OOB exfil / DSL injection),
and treat the RCE-chain lab as `risk: elevated`. Awaiting AUDITOR + operator sign-off.
