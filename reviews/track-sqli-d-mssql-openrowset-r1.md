# Review: batch/track-sqli-d-mssql-openrowset (PR #14, re-submit) — PASS

**Auditor:** denetle · **Head:** 58ec357 · **Re-review of:** reviews/track-sqli-d-mssql-openrowset (my FAIL) · **Base:** main
**Lab:** `sqli-mssql-stacked-openrowset-exfil` — final SQLi lab (25/25), 3rd heavy, first MSSQL, first cap_add lab.

## Verdict: PASS — both blocking CI defects fixed and verified; all 3 observations addressed. Cleared to merge. SQLi track complete after merge (25/25).

## Scope
Exactly the 6 fix files changed since 38ea188 (CHANGELOG.md, docs/tracks/sqli.md, SOLUTION.md, meta.json, src/seed.py, tests/checker.sh). No collateral changes.

## Both BLOCKING fixes — VERIFIED
- **BL-1 (format:check):** `prettier --check .` → "All matched files use Prettier code style!" Green. (CHANGELOG.md + docs/tracks/sqli.md now formatted.)
- **BL-2 (checker.sh):** line 4 now `TARGET="${1:-${TARGET:-http://127.0.0.1:8080}}"` (matches all 24 other labs). Verified LIVE via the CI invocation `sh checker.sh "http://127.0.0.1:18090"` → returned the flag, exit 0.

## Observations — all addressed
- **OBS-1:** SOLUTION.md now documents (lines ~100-102) that MSSQL-Linux CLR is SAFE-only — "MSSQL on Linux rejects UNSAFE and EXTERNAL_ACCESS assemblies (Msg 10342 …), so CLR cannot [run OS commands]." Accurate; strengthens the no-RCE lesson.
- **OBS-2:** meta.json declares `elevated_caps: ["NET_BIND_SERVICE"]` under risk:low. Meta schema VALIDATES (elevated_caps is permitted with risk:low — only risk:elevated→elevated_caps is coupled). CapAdd verified still exactly `[CAP_NET_BIND_SERVICE]`.
- **OBS-3:** seed.py secret → `HMAC-SHA256(secret, "mssql-secret|"+slug)[:32]` (was HMAC-MD5, no slug). Consistent with oracle/fortinet/copy-program. Verified LIVE: exploit exit 0, recovered secret == my independent SHA-256 derivation, flag matches — the derivation change did not break the exfil chain (exploit is derivation-agnostic; /solve compares DB value).

## No regression
Posture PASS (app=app/10001, db=mssql non-root, CapDrop=[ALL], CapAdd=[NET_BIND_SERVICE], read_only, no-new-privileges). Intended exploit exit 0, flag == independent HMAC. drift-lint 25 (partition 22+3=25), format, typecheck, meta-schema green. The security/design surface (no-RCE verified via the UNSAFE-CLR PoC → Msg 10342 SAFE-only; egress-drop; benign necessary cap; flag hygiene; trivy library=0/os=0; no baked flag) is unchanged by this patch — none of the 6 changed files touch it except seed.py's secret VALUE, re-verified above.

Clean, precisely-scoped fixes. This is the 25th and final SQLi lab.
