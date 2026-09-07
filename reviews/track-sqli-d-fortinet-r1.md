# Review: batch/track-sqli-d-fortinet (PR #11, re-submit) — PASS

**Auditor:** denetle · **Head:** 27cd375 · **Re-review of:** reviews/track-sqli-d-fortinet (my FAIL) · **Base:** main (clean ancestor)
**Lab:** `sqli-fortinet-ems-fctuid-rce`

## Verdict: PASS — BL-1 fixed and independently verified; cleared to merge. No further findings.

## BL-1 (was BLOCKING) — FIXED & VERIFIED LIVE
Fix (two-file patch, exactly my recommendation): `X-FCT-Host` is now BOUND — `src/app.py` builds `VALUES ('<fctuid>', %s, now())` and calls `cur.execute(sql, (hostname,))`. `X-FCTUID` stays concatenated as the SOLE, IPS-guarded injection point.
Independently re-verified in my worktree (27cd375):
- **Host injection CLOSED:** my exact probe — benign `X-FCTUID` + `X-FCT-Host: x', now()); COPY audit_log TO PROGRAM 'touch /tmp/HOST_INJECT_RETRY'; --` → HTTP 200 but NO file created.
- **Proven bound (not just blocked):** that malicious hostname was stored **literally** as the `devices.hostname` value (`SELECT hostname … = x', now()); COPY … --`), i.e. it went in as DATA, not SQL — the definitive proof of parameterisation.
- **IPS intact on the intended sink:** `X-FCTUID: a UNION SELECT b` → 403.
- **Intended lesson works:** table-source `COPY` via `X-FCTUID` → exploit exit 0, flag == independent HMAC, checker path OK.

## Cosmetic note — FIXED
`/solve` now uses `hmac.compare_digest` (constant-time); verified wrong-flag → 403. SOLUTION's class-of-bug snippet updated to show the bound `hostname` (`%s` + execute tuple) and explains WHY it must be bound ("not a second, unfiltered injection point").

## Regression sweep — all green
Posture PASS all 3 (app=app/10001, db=70:70, oob=app/10001). Image 142.7 MB, no baked flag (strict 0). format, drift-lint (22), gitleaks clean. SOLUTION 9 H2 sections. Scope clean (only src/app.py + SOLUTION.md changed since the FAIL; packages/schema untouched). Containment (db+oob egress-drop), superuser-intentional/risk:low, OOB collector, flag hygiene, trivy library=0/os=0 — all unchanged from my prior PASS on those axes (requirements.txt identical; networks/db/oob untouched).

Clean, precisely-scoped fix. The lab now actually teaches the IPS-evasion it advertises.
