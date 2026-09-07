# Review: batch/track-sqli-d-moveit (PR #10) — FAIL

**Auditor:** denetle (independent adversarial verification) · **Head:** 1d0567e · **Base:** main (clean ancestor)
**Lab:** `sqli-moveit-header-auth-bypass-chain` — CVE-2023-34362 (MOVEit) abstraction; header SQLi → session forgery → file exfil. First MSSQL→Postgres re-platform.

## Verdict: FAIL — one BLOCKING security-posture defect (BL-1). Intended path works and all standard gates are green; this is a latent DB-role misconfig, not a design flaw. Small fix, then re-review.

## BL-1 (BLOCKING · security-posture · unintended RCE + open egress)
**Where:** `docker-compose.yml:68` (`POSTGRES_USER: moveitapp`) + `src/app.py:74-82` (audit `.execute()` sink) + `docker-compose.yml:99-103` (`labnet internal:false`).
**What:** The app's DB role `moveitapp` is a Postgres **superuser** (the postgres image makes `POSTGRES_USER` a superuser). The injectable audit sink runs via psycopg2 `.execute()` (stacked statements), so the SAME injection that forges a session also permits `COPY … FROM/TO PROGRAM` — i.e. **RCE inside the DB container**. And `labnet` is `internal:false`, so that container has **open egress**.
**Proven live (this review):**
- `SELECT usesuper` for moveitapp → `t` (superuser).
- Sent `X-siLock-Comment: x', '0.0.0.0', now()); COPY (SELECT 1) TO PROGRAM 'touch /tmp/PWNED_BY_AUDITOR'; --` → HTTP 200, and `/tmp/PWNED_BY_AUDITOR` appeared in the DB container (owned by postgres). **RCE confirmed.**
- From the DB container: default route present, outbound TCP to `1.1.1.1` succeeded → **egress OPEN**.
**Why it blocks:** The lab is declared `risk:low` with an explicit "no RCE" framing, but ships a trivially-reachable, un-contained RCE with phone-home capability — regressing the containment standard the copy-program lab (PR #9) set one batch ago for this exact superuser+COPY-PROGRAM primitive. The risk classification is materially inaccurate for the actual attack surface. (RCE is sandbox-contained — cap_drop:ALL/read_only/non-root/no-new-privileges all hold — so no container escape, but open egress from an unintended RCE is still a real posture gap on a self-hosted platform.)
**Fix (preserves the lesson):** Connect the app AND seed's runtime as a **non-superuser** role with only `INSERT` on `audit_log` + `SELECT` on `sessions`,`users` (+ sequence `USAGE`) — created via init SQL run once by the bootstrap superuser (which can still own/CREATE the tables at init). A non-superuser cannot `COPY … PROGRAM`, so the unintended RCE closes, `risk:low` becomes honest, and the intended stacked-`INSERT INTO sessions` forgery still works (plain INSERT needs no superuser). Optional defense-in-depth: also move the DB onto an `internal:true` egress-drop network, mirroring copy-program.

## BL-2 (minor · docs) — `SOLUTION.md`
7 H2 WHY-sections; the per-lab bar is ≥8. Add one — a natural fit is a "Least privilege / why the DB role matters" section that also carries the BL-1 fix rationale.

## BL-3 (minor · CWE precision) — `meta.json:17`, `SOLUTION.md:4`
Auth-bypass labelled **CWE-384 (Session Fixation)**. Forging a brand-new admin session row via SQLi is more precisely an authorization/authentication bypass — e.g. CWE-565 (Reliance on Cookies without Validation) or CWE-290 (Auth Bypass by Spoofing). CWE-384 is defensible-ish but imprecise; either switch or add a one-line justification. (Enum note: CWE-565/CWE-290 would need adding to `packages/schema/enums.json` if you switch.) Non-blocking judgment call.

## Answers to your three review-focus questions
1. **No unintended READ-path leak — CONFIRMED.** `sessions` is seeded empty (no admin token to steal); `_valid_admin_session`/`/login`/`/solve` are parameterised; `/login` is a stub that never issues a session even on valid creds, so error-based extraction of the sysadmin password is useless. The intended WRITE-path forgery is the only *read*-safe route — BUT the WRITE-path also reaches RCE (BL-1).
2. **Re-platform fidelity MSSQL→Postgres — ACCEPTABLE / faithful.** psycopg2 `.execute()` stacks `;`-statements exactly like the MSSQL `SqlCommand` primitive (verified live). Hybrid-policy compliant; catalog reconciled to the shipped Flask/Postgres stack.
3. **Per-container flag.bin hygiene — CONFIRMED good.** flag.bin is 4KiB HMAC-derived (instance-unique sha256 bb9316…), never contains the flag; secret absent from the DB container; no FLAG in any table; flag returned only by `/solve`; no baked flag/flag.bin in the image.

## Everything else (green — for the fast re-review after BL-1)
Intended exploit exit 0 (403→forge→200→solve, flag == independent HMAC), checker solved. Posture PASS both (app=app/10001, db=70:70, read_only, cap_drop:ALL, no-new-privileges, pids+mem, app loopback-only, db no host port, tmpfs). Image 142.7 MB. trivy library=0 / os=0 (debian 13.6; Flask 3.1.0/gunicorn 23/psycopg2 2.9.10). gitleaks 46 commits clean. drift-lint (21 impl, catalog byte-matches meta), map, typecheck (5), format, dockerfile-pin (21), meta schema-valid (A07+CWE-384 already in enums.json allowlist — note the PR does not modify packages/schema/, they were pre-existing). Scope clean (lab dir + CHANGELOG/catalog/track-doc). Hints 1-3 progressive.
