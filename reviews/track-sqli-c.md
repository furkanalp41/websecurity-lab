# AUDITOR review — batch `track-sqli-c`

- **Branch / head:** `build/sqli-c` @ `a1f00ff84cdf7b85814f9cd65ecee59bd0fead00`
- **PR:** #6 · **Base:** `main` @ `3fc4391`
- **Labs (6, native-stack, Hybrid "diversity" batch):** json-body-prisma-raw, mongo-operator-login-bypass, couchdb-mango-selector (practitioner); django-extra-orm, rails-active-record-hash, graphql-batch-prisma-raw (expert)
- **Verdict:** **`PASS_WITH_FINDINGS`** — merge allowed. Every security and functional gate passed independent hand-verification; all findings are documentation/metadata completeness (P1/P2), none block merge. 8 backlog items → a consolidated `chore-sqli-c-docs` batch is recommended.

Everything below was hand-run; CI green was corroborating, not sole, evidence.

## Dynamic gauntlet (serial, live Docker) — 6/6 GREEN
| lab | build | MB | baked FLAG | posture (app+db) | exploit | time | flag==HMAC | checker |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| json-body-prisma-raw | ✓ | 188 | 0 | GREEN (app,70) | exit 0 | <1s | ✓ | PASS |
| mongo-operator-login-bypass | ✓ | 148 | 0 | GREEN (app,999) | exit 0 | 2s | ✓ | PASS |
| couchdb-mango-selector | ✓ | 152 | 0 | GREEN (app,5984) | exit 0 | <1s | ✓ | PASS |
| django-extra-orm | ✓ | 172 | 0 | GREEN (app,70) | exit 0 | <1s | ✓ | PASS |
| rails-active-record-hash | ✓ | 197 | 0 | GREEN (app,70) | exit 0 | <1s | ✓ | PASS |
| graphql-batch-prisma-raw | ✓ | 204 | 0 | GREEN (app,70) | exit 0 | 1s | ✓ | PASS |

No baked flag in any image (`docker export` of the un-started image → 0). Posture gate green on BOTH containers of every lab, including the new non-root DB patterns (MongoDB uid 999 + tmpfs /data/db + `/dev/tcp` healthcheck that correctly avoids the mongosh-OOM trap; CouchDB uid 5984 + tmpfs data/etc). Each exploit recovered a flag matching one I derived independently from the same secret.

## Other independent gates
- **trivy 0.74.0 two-call gate (my rebuild+scan):** all 6 images exit 0 on library HIGH/CRITICAL AND os CRITICAL. Validates the builder's runtime npm-strip (graphql/mongo/json-body) and the ruby stale-resolv-gem removal (rails).
- **Base-image digests:** all 6 (node/ruby/couchdb/mongo/postgres/python) resolve in the registry — the two previously-fabricated digests (node, ruby) are now genuinely real.
- **gitleaks 8.21.2 over 32 commits:** no leaks; `.gitleaksignore` unchanged (the 3 prior FPs were genericized, not suppressed — correct).
- **Repo gates:** prettier, `catalog`+drift-lint (18 labs, catalog tech_stack == meta for all six), map, lint, typecheck, 18/18 Dockerfiles digest-pinned — all green.
- **CI (build/sqli-c, run 34038182602):** completed/success — all required jobs + all 18 docker-lab-matrix (incl. rails).

## Per-lab authenticity (the decisive check) — all genuine
- **json-body:** `prisma.$queryRawUnsafe(sql)` with a JSON-body value concatenated (not the safe tagged template); UNION exfil; fix = parameterization. Real CWE-89.
- **mongo (CWE-943):** raw `req.body` → native `findOne`, no cast/strip; `$ne` auth bypass + `$regex` blind extraction of the 64-hex reset_token. `/solve` non-injectable. Genuine NoSQL operator injection.
- **couchdb (CWE-943):** `{**OWNER_CONSTRAINT, **client_filter}` client-wins merge → owner-filter bypass to read flag_holder.secret; fix ANDs server-side. Genuine.
- **django:** unbound f-string into `.extra(where=[...])` (not the safe `params=`); UNION reads auth_user.password of superuser `root`; `/solve` parameterized. Genuine.
- **rails (hand-finished — scrutinized hardest):** `Arel.sql(params[:sort])` → `.order(...)` ActiveRecord ORDER BY injection; CASE-flip ordering oracle extracts the 16-hex master_key. **The hand-fix is correct and verified live**: entrypoint boots via `ruby -e 'require config/environment; load db/seed_lab.rb'` (not the no-op `rails runner`), tables+rows are created, exploit lands. Boot path sound (Bundler.require swallows the component-gem autorequire LoadErrors).
- **graphql:** `$queryRawUnsafe` reached via genuinely-uncapped GraphQL field-alias batching (no depth/complexity/alias limits, no validation rules); blind boolean oracle via swallowed errors; exploit batches ~128 aliases/request to extract the 40-hex batch_flag. npm + its dep tree stripped from the runtime stage (confirmed). Genuine.

Documented deviations VALIDATED: rails 16-hex master_key (fits <60s) and all `/solve` endpoints reading the flag file in-process (no shell-exec) are both justified in SOLUTION/track-doc.

## Findings → backlog (all P1/P2; none block merge)
| id | lab(s) | sev | item | fix |
| --- | --- | --- | --- | --- |
| BL-1 | json-body, rails | P1 | SOLUTION documents <3 distinct payload vectors (json-body: 2; rails: 1 — the ordering oracle only) | add ≥3 distinct vectors each (e.g. arity/ORDER BY discovery, error/boolean-oracle variant) |
| BL-2 | all 6 | P2 | SOLUTION.md lacks an explicit `CVE: <id or N/A>` line (rubric = CWE+OWASP+CVE-or-N/A); mongo SOLUTION also lacks the OWASP line (present only in README) | add the CVE/N-A line to all 6; add OWASP A03 to mongo SOLUTION |
| BL-3 | json-body | P2 | `data/catalog.json` prose inaccurate — says `SELECT * FROM reports` (src: `SELECT id,title,status`) and lists skill "Postgres UNION with jsonb columns" (no jsonb; text cols) | correct description + skill (drift-lint only checks tech_stack, not prose) |
| BL-4 | couchdb | P2 | `meta.json` inspired_by cites CVE-2022-24706 (CouchDB Erlang-dist RCE) — unrelated to Mango selector injection | drop or replace with a genuine NoSQLi analog / "N/A" |
| BL-5 | django | P2 | `Django==5.1.14` is security-EOL (2025-12-03) — final 5.1 patch so no *unpatched* CVE, but rubric wants a supported release | bump to Django 5.2.x LTS; update meta tech_stack |
| BL-6 | rails | P2 | version drift: README/`application.rb` load_defaults/Gemfile comments say 7.1 but ships 7.2.3; stale "via rails runner" comment (seed_lab.rb:4); leftover nokogiri Dockerfile comment + fragile `rm -rf */ext`; README time 35 vs meta 45; `permit(:category)` for a nonexistent column | reconcile to 7.2 everywhere; remove dead comments; align time; drop `category` (or add column) |
| BL-7 | graphql | P2 | cosmetic mangled backticks (SOLUTION.md:38-39); README spells out the breakout (hint-2 depth); objective mentions resolver rate-limits that don't exist | fix markdown; tone down README; align objective |
| BL-8 | mongo, django | P2 | `exposed_service.http_path` points at a POST-only route (/login, /search) — a GET liveness probe there would 404 | point http_path at a GET route (e.g. /health) or confirm the runner doesn't GET it |

Explicitly checked and cleared (NOT findings): committed `.pyc` (0 tracked in git — on-disk only); puma 7.2 / cryptography resolvability (all images built); `.gitleaksignore` unchanged.

## Path
Merge is not blocked. Recommend the builder fold BL-1..BL-8 into a single `chore-sqli-c-docs` batch (docs/metadata/version-currency only — no lab src/exploit change, so a light re-review). BL-1 (payload-vector breadth) and BL-5 (Django EOL bump) are the two worth prioritizing.
