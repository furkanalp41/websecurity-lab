# Review: batch/track-sqli-d-moveit (PR #10, re-submit) — PASS

**Auditor:** denetle · **Head:** 43b142b · **Re-review of:** 57c47f0 (my FAIL) · **Base:** main (clean ancestor)
**Lab:** `sqli-moveit-header-auth-bypass-chain`

## Verdict: PASS — BL-1 fixed and independently verified; cleared to merge. Two residual cosmetic CWE-384 refs (non-blocking) noted for a quick sweep.

## BL-1 (was BLOCKING) — FIXED & VERIFIED LIVE
Fix: app connects as a NON-superuser role `moveitapp` (created by `db-init/01-init.sql`, run once by bootstrap superuser `moveit_admin`); grants limited to INSERT audit_log / INSERT+SELECT sessions / SELECT users / sequence USAGE. DB moved onto an `internal:true` egress-drop `backend` net (app dual-homed edge+backend). seed.py deleted.
Independently re-verified in my worktree (43b142b):
- **Role is non-superuser:** error-based leak through the audit sink → `current_user="moveitapp"`, `is_superuser="off"`; `pg_roles.rolsuper(moveitapp)=false`.
- **RCE closed:** my exact probe `X-siLock-Comment: x', '0.0.0.0', now()); COPY (SELECT 1) TO PROGRAM 'touch /tmp/PWN_RE'; --` → HTTP 200 but NO file created (permission denied for non-superuser).
- **Escalation closed:** stacked `SET ROLE moveit_admin; COPY … TO PROGRAM …` → NO file (moveitapp is not a member of the superuser role).
- **Egress dropped:** db on `backend` only (Internal=true); `/proc/net/route` has only the on-link `172.20.0.0/16` route, NO default route (Destination 00000000 absent); outbound DNS + TCP to 1.1.1.1 both blocked.
- **Intended lesson intact:** the plain stacked `INSERT INTO sessions` forgery still works → exploit exit 0, flag == independent HMAC, 403 before forgery → 200 after; checker solved.
(Note: two of my first-pass probe readings — a "default route" hit and a `pg_stat_activity` "moveit_admin" row — were MY measurement artifacts: a `grep 00000000` matching the Gateway column, and my own `psql -U moveit_admin` probe connection. Both corrected with precise tests above; the fix is sound.)

## BL-2 (was minor) — FIXED
SOLUTION.md now has 8 H2 sections, incl. the new "Least privilege: why the app's DB role matters" carrying the BL-1 rationale.

## BL-3 (was minor) — SUBSTANTIVELY FIXED, 2 residual refs (NON-BLOCKING)
`meta.json` cwe_ids → `["CWE-89","CWE-565"]` (CWE-565 in enums allowlist); SOLUTION header → CWE-565. **Residual:** `meta.json:29` still carries the stale tag `"cwe-384"`, and `SOLUTION.md:19` prose still says "authentication bypass (CWE-384)" — now contradicting the CWE-565 header. Cosmetic doc-consistency; sweep at merge or in a follow-up. Not blocking.

## Regression sweep — all green
Posture PASS both (app=app/10001, db=70:70, read_only, cap_drop:ALL, no-new-privileges, pids+mem, app loopback-only, db no host port, tmpfs; db bind-mounts db-init:ro — benign, rootfs still read_only). Image 142.6 MB. trivy library=0 / os=0. gitleaks clean (init-SQL lab creds don't trip it). drift-lint (21 impl, catalog byte-matches meta), map, typecheck (5), format, dockerfile-pin (21), meta schema-valid. No baked flag (strict 0). Flag hygiene intact (secret absent from db, no FLAG in tables, flag.bin instance-unique). Scope clean (lab dir + CHANGELOG/catalog/docs; packages/schema/ untouched — CWE-565 pre-existing in enums).

Good, responsive fix — the least-privilege role is exactly right and preserves the session-forgery-by-writing-state lesson.
