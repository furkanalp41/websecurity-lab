# Review: batch/track-sqli-d-copy-program (PR #9) — PASS

**Auditor:** denetle (independent adversarial verification) · **Head:** db6b6a7 · **Base:** main (clean ancestor)
**Lab:** `sqli-postgres-copy-program-rce-chain` — the project's FIRST SQLi→RCE lab, elite. Abstracts Postgres `COPY FROM PROGRAM` superuser RCE (Adrien Peter research / GitLab #827052).

## Verdict: PASS — cleared to merge. No blocking findings. I CONCUR with risk:low (verified empirically; it is the honest and stricter posture).

## Scope
Clean: new lab dir + three expected repo touchpoints (CHANGELOG, data/catalog.json Hybrid reconcile, docs/tracks/sqli.md). No `.github/workflows` change — consistent with risk:low (no meta.risk→LAB_RISK wiring, correctly not built).

## Special asks — both verified LIVE
- **Item #1 (risk:low justification):** `docker inspect db` → `CapDrop=[ALL]`, `CapAdd=null`, Privileged=false, ReadonlyRootfs=true, User=70:70. The RCE then LANDED under exactly that sandbox (exploit exit 0) — proving `COPY FROM PROGRAM` needs ZERO added Linux caps. risk:low is empirically correct; declaring elevated would relax cap_drop for nothing and force a dishonest `elevated_caps`. Concur.
- **Item #4 (egress-drop live test):** from the DB container (the RCE target): **no default route** (`/proc/net/route` shows only on-link `172.18.0.0/16`, no `00000000`), outbound DNS (`getent hosts example.com`) times out, outbound TCP to `1.1.1.1` blocked. DB reaches only the in-lab app over `backend`. §13 egress-drop confirmed. (Note: app is dual-homed edge+backend to bridge the loopback port; it exposes no proxy/forwarding primitive, so it is not a pivot-to-egress path — acceptable and necessary.)

## The RCE chain (verified live)
Two sinks, both real asyncpg semantics: `GET /metrics?category=` uses `.fetch()` (extended/prepared protocol → single statement → UNION-visible readback); `POST /metrics/ingest {source}` uses `.execute()` no-args (simple protocol → stacked `;` allowed → RCE sink). Exploit: ingest stacks `DROP/CREATE loot; COPY loot FROM PROGRAM 'cat /labflag/flag.txt'`, then UNION-reads `loot` via /metrics, then /solve. **exit 0 in 0.11s** (3 requests), flag == independent `hmac_sha256(LAB_USER_SECRET,"v1|"+slug)`. checker: solved. App confirmed `usesuper=true` (the taught misconfig).

## Flag hygiene (critical for an RCE lab — verified live)
- Raw `LAB_USER_SECRET` is NEVER sent to Postgres (compose `db` env has none; `docker exec db env` shows no secret) → an in-DB RCE recovers THIS instance's flag (the objective) but cannot re-derive other instances' flags.
- Flag planted on the DB fs (`/labflag/flag.txt`, tmpfs) via seed's superuser `COPY (SELECT '<flag>') TO` — the derived flag STRING, not the secret. Flag is NOT in any seeded table (`metrics`,`events`) → no SQL-SELECT shortcut; command execution is mandatory.
- No baked flag: strict `FLAG{[0-9a-f]{64}}` count in app image fs = **0** (the loose `1` was `seed.py:90`'s comment "the flag is FLAG{64 lowercase hex}"). Secret unset before uvicorn.

## Security posture / infra
Posture gate PASS both containers (app=app/10001, db=70:70, read_only, cap_drop:ALL, no-new-privileges, pids+mem, app port loopback-only, DB publishes no host port, tmpfs datadirs incl /labflag uid 70). Image 156.7 MB. Dockerfiles digest-pinned (python:3.12-slim, postgres:16-alpine). trivy: **library HIGH,CRITICAL = 0** (starlette 1.6.0 / uvicorn 0.52.4 bumps cleared the 3 starlette HIGH CVEs), **os CRITICAL = 0** (debian 13.6). gitleaks: 42 commits, no leaks.

## Repo gates (all exit 0)
catalog drift-lint (20 implemented; catalog tech_stack byte-matches meta after reconcile to FastAPI 0.141/asyncpg 0.30/PG 16.15) · map · typecheck (5 projects) · format:check · dockerfile digest-pin (20) · meta.json schema-valid (2020-12), id==dir.

## Docs / pedagogy
SOLUTION: 8 WHY-sections, 3 payload vectors (arbitrary file read / lo_import+pg_read_file / single-table readback), OWASP A03 + CWE-89→CWE-78 + CVE-analog, fix rationale (least-privilege DB role, parameterise, revoke COPY PROGRAM), risk:low deviation documented. Hints 1-3 progressive (visible SQLi → stacked-vs-prepared + usesuper → full COPY PROGRAM chain). Catalog reconcile honest (old single-chain /flag.txt description → real two-sink /labflag chain + risk:low).

## Non-blocking observations (courtesy — not backlog items)
- OBS-1: catalog `inspired_by` ("2019 Adrien Peter DEF CON talk") wording differs slightly from meta.json `inspired_by`; drift-lint doesn't gate on it and both are honest attributions. Cosmetic.

## Forward-policy note (operator's call, non-blocking)
This is the platform's first RCE lab. Per CLAUDE.md the elevated tier is tied to needing relaxed sandbox/caps — which this lab does not — so risk:low is charter-correct and I passed on it. IF the operator later wants RCE labs to carry a learner-facing signal (risk:elevated + red confirm) regardless of caps, that is a precedent-setting product policy for the many RCE labs ahead; absent that ruling, the current charter reading (risk:low) stands and I will keep applying it.
