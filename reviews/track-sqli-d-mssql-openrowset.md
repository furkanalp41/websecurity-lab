# Review: batch/track-sqli-d-mssql-openrowset (PR #14) — FAIL

**Auditor:** denetle (max-effort) · **Head:** 38ea188 · **Base:** main (6b9ffc3, clean ancestor)
**Lab:** `sqli-mssql-stacked-openrowset-exfil` — final SQLi lab (25/25), 3rd heavy-tier, first MSSQL, first cap_add lab. expert, risk:low, resource_tier:heavy.

## Verdict: FAIL — two CI-breaking mechanical defects (BL-1, BL-2). NOT a security/design problem — the security is genuinely sound (no-RCE verified end-to-end, contained, honest risk:low). Both fixes are one-liners; fast re-review.

## BL-1 (BLOCKING · CI gate) — format:check FAILS
`prettier --check .` flags **CHANGELOG.md** and **docs/tracks/sqli.md** as unformatted (this PR's edits to them weren't prettier-formatted). format:check runs on EVERY PR → this PR would be red. Fix: `pnpm run format` (or `prettier --write CHANGELOG.md docs/tracks/sqli.md`) + commit.

## BL-2 (BLOCKING · CI gate) — checker.sh incompatible with the CI invocation
`tests/checker.sh:4` is `: "${TARGET:?TARGET is required ...}"` — it requires the TARGET **env var** and ignores `$1`. But BOTH ci.yml (:175) and heavy-nightly.yml (:102) invoke `sh "<lab>/tests/checker.sh" "http://127.0.0.1:${LAB_HOST_PORT}"` — passing the URL as **$1**. Every other lab's checker is `TARGET="${1:-${TARGET:-http://127.0.0.1:8080}}"`. So in heavy-nightly this checker fails "TARGET is required" → the lab's nightly checker step goes red (and trips the C3 rolling issue). Fix: line 4 → `TARGET="${1:-${TARGET:-http://127.0.0.1:8080}}"` (match the other 24 labs). (Verified: with TARGET env set the checker DOES return the flag — the exploit is fine; only the arg-handling is wrong.)

## SECURITY / DESIGN — sound (verified LIVE, max effort). This is the reason it's "fix the plumbing", not "rework the lab".
- **"No host-level command execution" — TRUE, verified airtight.** I audited every MSSQL-on-Linux sysadmin RCE path as SA:
  - xp_cmdshell → blocked ("not supported by this edition", Msg 15392/15281). OLE `sp_OACreate` → blocked (same). SQL Agent → **Stopped** (no CmdExec).
  - CLR: I built a REAL command-exec SQLCLR assembly with `dotnet` (System.Diagnostics.Process → /bin/sh), and MSSQL-Linux **rejected both UNSAFE and EXTERNAL_ACCESS** with Msg 10342 "this edition of SQL Server only supports SAFE assemblies." SAFE CLR cannot spawn processes, do file I/O, or P/Invoke → no CLR RCE, no CLR file/network. (Note: the "malformed assembly" you get from an invalid blob is a FALSE positive — it's rejected before the permission check; a valid UNSAFE assembly hits the SAFE-only gate.)
  So a MSSQL-Linux sysadmin genuinely cannot reach OS command execution here. risk:low is honest.
- **Egress-drop:** db → no default route, db→1.1.1.1:443 = Network unreachable. Contained regardless.
- **cap_add:NET_BIND_SERVICE — verified benign, necessary, only-one.** `docker inspect` → CapDrop=[ALL], CapAdd=[CAP_NET_BIND_SERVICE] exactly; db runs non-root (mssql). It's a Docker-default cap (no privilege escalation — only <1024 binding) and genuinely required (sqlservr's `cap_net_bind_service=ep` file-capability binary can't execve under cap_drop:ALL + no-new-privileges without it). risk:low is correct — declaring risk:elevated would counterproductively RELAX the posture gate's cap_drop check.
- Posture gate green (app=app/10001, db=mssql non-root, read_only, no-new-privileges, pids/mem). Intended exploit exit 0 (stacked INSERT secrets→notices → /notices → /solve; recovered secret + flag both == my independent HMAC). Flag hygiene: raw LAB_USER_SECRET absent from db env AND schema (only the derived secret). No baked flag/secret. app image 145.5 MB. trivy library=0/os=0. gitleaks clean. drift-lint 25, partition 22 std + 3 heavy = 25 (C1 sums). typecheck, dockerfile-pin (24... note count below), meta-schema green. OPENROWSET(BULK) file-read works, contained to the DB container.

## Non-blocking observations
- OBS-1 (SOLUTION accuracy): SOLUTION line ~99 lists "CLR assemblies" among vectors "that work on the Linux kernel", with NO SAFE-only caveat. Per my PoC, Linux MSSQL is SAFE-CLR-only → CLR gives NO command exec / file / network on Linux. Add the caveat — it strengthens the lesson (xp_cmdshell + OLE + UNSAFE-CLR + Agent ALL unavailable on Linux ⇒ the real defense is least-privilege, not the platform). Also: the OPENROWSET file-read genuinely IS a working Linux vector; keep that.
- OBS-2 (cap transparency / PRECEDENT — first cap_add lab): the added cap is documented in compose but NOT machine-readable in meta. Recommend `elevated_caps: ["NET_BIND_SERVICE"]` in meta.json while keeping risk:low (the schema permits elevated_caps under risk:low; only the reverse is coupled). This makes the deviation auditable and would let a future CI check diff CapAdd vs declared elevated_caps — the posture gate is currently blind to cap_add. (Surfacing the precedent to the operator.)
- OBS-3 (secret derivation cosmetic): mssql_secret = HMAC-**MD5**(secret,"v1|mssql-secret") — other labs use SHA256[:32] and include the slug. Per-container-unique so functionally fine; inconsistent. Cosmetic.

Genuinely strong lab under the hood — the "is Linux MSSQL sysadmin actually RCE-safe?" question is subtle and you got it right (I verified with a real CLR PoC). Just fix the two CI-plumbing breaks (format + checker arg) and it's a PASS.
