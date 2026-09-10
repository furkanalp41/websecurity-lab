# Review: batch/track-sqli-d-oracle-oob (PR #13) — PASS

**Auditor:** denetle · **Head:** 61e5ae0 · **Base:** main (7b57f06, clean ancestor)
**Lab:** `sqli-oob-dns-oracle-utlhttp` — first Oracle lab, second heavy-tier. SQLi → UTL_HTTP OOB exfil (scalar-subquery in a concatenated WHERE). expert.

## Verdict: PASS — cleared to merge. No blocking findings. Three non-blocking observations noted.

## Your four review-focus asks — all VERIFIED LIVE (max-effort adversarial pass)
1. **Egress-drop containment:** db → no default route, db→1.1.1.1:443 = "Network is unreachable", db→oob:9000 = reachable. AND (my extra check) oob → no default route, oob→1.1.1.1 blocked. So even a fully-granted UTL_HTTP call reaches ONLY the in-lab collector — no db→oob→internet pivot. Both required halves hold.
2. **UTL_HTTP ACL scope — narrow, no image-default leak:** queried `dba_host_aces` as SYS@XEPDB1 — REPORTAPP's ONLY network ACE is `host='oob', ports 9000-9000, HTTP`. No wildcard host, no other host, and no PUBLIC ACE (`host<>'oob' for REPORTAPP/PUBLIC` → 0 rows). The ACL is the universal gate for UTL_TCP/HTTP/SMTP/INADDR, so even those can only reach oob:9000.
3. **risk:low justification — PROVEN, not asserted:** full REPORTAPP privilege audit as SYS: roles = CONNECT + RESOURCE only; sys privs = CREATE VIEW/SYNONYM/MATERIALIZED VIEW (benign); EXECUTE object grants = **only `SYS.UTL_HTTP`**; RCE-shaped privs (ANY/JOB/JAVA/EXTERNAL, DBMS_SCHEDULER, UTL_FILE, DBMS_JAVA) = NONE. So there is genuinely no OS-command / file-write / job / Java path — UTL_HTTP is a network primitive, not a shell. Same principle as ES; honest.
4. **Oracle hardening deviations — acceptable & working:** Oracle 21c XE (gvenzl slim-faststart, digest-pinned) runs under FULL posture — non-root uid 54321, read_only rootfs, cap_drop:ALL, no-new-privileges, pids/mem 2g. The deviations are empirically necessary and documented: anonymous volumes for /opt/oracle/{oradata,dbs,homes,admin,diag} (datafiles too big for a RAM tmpfs; bare tmpfs would wipe the pre-seeded PDB), tmpfs:exec on /tmp+/var/tmp (JNA mmap+exec + TNS IPC socket), no ORACLE_DATABASE (uses pre-seeded XEPDB1). posture gate green on all 3.

## Standard gauntlet — GREEN
Posture PASS all 3 (app=app/10001, db=54321:54321, oob=app/10001). Intended exploit exit 0 (scalar-subquery UTL_HTTP → OOB collector → /solve; recovered oracle_secret matched my independent HMAC, flag == independent HMAC), checker solved. Flag hygiene: raw LAB_USER_SECRET absent from db env AND not present in the reportapp schema (only the DERIVED 32-hex secret; the raw secret never reaches Oracle); 2 app tables only; flag app-side; seeded secret == my expected value (fresh per-container seed). No baked flag (strict FLAG{64hex}=0) and no baked secret in the app image. app image 159.9 MB. trivy library=0 / os=0 (debian 13.6; Flask 3.1.0/gunicorn 23.0.0/oracledb 4.0.2/cryptography 50.0.1/werkzeug 3.1.8 all clean). gitleaks 61 commits no leaks. drift-lint (24 impl; resource_tier:heavy honored), partition 22 standard + 2 heavy = 24 (C1 sums), format, typecheck (5), dockerfile-pin (24), meta schema-valid (CWE-89+CWE-918). Scope clean (lab dir + CHANGELOG/catalog/docs; no CI/schema changes — builds on the merged heavy-tier plumbing).

## Docs / pedagogy
SOLUTION 8 H2 sections incl. "Why UTL_HTTP works here (network ACL surprise)" + "Why RCE isn't the play here" + all deviations (Java/Spring→Python/Flask re-platform per Hybrid policy; Oracle hardening). 3 payload vectors (scalar-subquery / OR-context / XMLTYPE) + a UTL_INADDR DNS-ACL note. Fix rationale (don't grant UTL_HTTP, keep ACLs narrow, egress-drop). Hints 1-3 progressive. **exploit.py docstring is clean and accurate** — you clearly folded in the ES lesson (no exploration-note drift, no false claims). Nice.

## Non-blocking observations (courtesy — no lab-file change needed)
- OBS-1 (operational): the anonymous Docker volumes persist Oracle's datadir (incl. the per-container derived secret in the datafiles, ~1 GB) on the host until `compose down --volumes`. Necessary for Oracle and documented, and heavy-nightly.yml uses `down --volumes`. But ensure **labctl's local teardown also passes `-v`** for heavy labs, or a learner accumulates GB-scale volumes + stale per-instance secrets on disk. This is a platform/labctl concern, not a lab-file fix. (This lab is the first to use volumes vs the tmpfs-ephemeral norm — worth codifying the `-v` teardown convention before mssql lands.)
- OBS-2 (cosmetic): `entrypoint.sh:17` comment says "GRANT EXECUTE ON UTL_HTTP + DBMS_LOCK" but seed.py grants only UTL_HTTP (no DBMS_LOCK). Stale comment.
- OBS-3 (cosmetic): `app.py:32` `DB_SERVICE` default "REPORTS" is dead (compose sets XEPDB1; seed.py defaults XEPDB1). Harmless inconsistency.

Excellent lab. The containment story is airtight and I verified it end-to-end at the privilege/ACL layer, not just the network layer. sqli 24/25 — only mssql-xp-cmdshell remains.
