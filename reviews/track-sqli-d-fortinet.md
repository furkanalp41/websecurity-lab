# Review: batch/track-sqli-d-fortinet (PR #11) — FAIL

**Auditor:** denetle · **Head:** 43366ab · **Base:** main (clean ancestor)
**Lab:** `sqli-fortinet-ems-fctuid-rce` — CVE-2023-48788 abstraction; header SQLi → COPY-TO-PROGRAM RCE → OOB exfil. First OOB-exfil + IPS-evasion lab; last MSSQL abstraction.

## Verdict: FAIL — one BLOCKING defect (BL-1) that defeats the lab's headline IPS-evasion lesson. Containment, intended exploit, and all other gates are green; the fix is a one-liner.

## BL-1 (BLOCKING · pedagogy/correctness · the IPS guards only one of two injectable inputs)
**Where:** `src/app.py:100-111`. The IPS (`ips_block`) is applied ONLY to `X-FCTUID` (line 101). But `X-FCT-Host` (line 107) is concatenated into the SAME INSERT (line 108-111) and is **never IPS-checked**.
**Proven live (this review):**
- `X-FCTUID: a UNION SELECT b` → 403 (IPS works on the intended header).
- Benign `X-FCTUID: DEV-benign` + `X-FCT-Host: x', now()); COPY audit_log TO PROGRAM 'touch /tmp/HOST_INJECT_AUDITOR'; --` → HTTP 200 and the file appeared in the DB container → **full RCE through the unfiltered second header, bypassing the IPS entirely.**
- `X-FCT-Host: a UNION SELECT b` → HTTP 200 (not blocked) — the IPS never inspects this header.
**Why it blocks:** this lab's defining, advertised feature is IPS-evasion ("first IPS-evasion lab"; learning-objective #3 is "evade a naive keyword IPS … by using a table-source COPY"). A learner can inject through `X-FCT-Host` with ANY payload and never encounter the IPS — the clever table-source-COPY tradecraft the lab is built to teach becomes unnecessary. `X-FCT-Host` is never mentioned in SOLUTION/README/hints, so this is an unacknowledged oversight, not a deliberate design choice. (Same principle as the moveit FAIL: the lab's claimed central property doesn't actually hold.)
**Fix (small; intended path unaffected):** **parameterise `hostname`** — bind it: `cur.execute("INSERT INTO devices (fctuid, hostname, registered_at) VALUES (%s, %s, now())", (fctuid, hostname))` won't work while `fctuid` must stay injectable, so instead keep `fctuid` concatenated (the IPS-guarded injection point) and bind ONLY `hostname`, e.g. build the string with `fctuid` and pass `hostname` via a `%s` placeholder + arg. That leaves `X-FCTUID` as the sole, IPS-guarded injection point and forces the table-source-COPY bypass. (Alternative: run `ips_block` on `hostname` too / on the assembled value, keeping two injectable-but-filtered inputs.) Note: the SOLUTION's own Fix section already advocates parameterising both inputs — apply that spirit to the lab's own second input.

## Containment / charter — VERIFIED GOOD (your review-focus asks)
- **Egress-drop live (both RCE-reachable containers):** db → no default route, db → 1.1.1.1 blocked, db → oob:9000 works. **oob → no default route, oob → 1.1.1.1 blocked** (my extra check — so there is no db→oob→internet pivot; the collector itself can't exfil off-host). The only reachable listener from the RCE is the in-lab collector. Exactly right.
- **Superuser-as-intentional — charter-correct:** `is_superuser=on` for emsapp; COPY-TO-PROGRAM RCE runs under cap_drop:ALL + read_only + non-root uid 70 + no-new-privileges (zero added caps), contained by the egress-drop network. risk:low is honest here (unlike moveit, where superuser was unintended). Concur.
- **IPS honesty vs pedagogy:** the naive-keyword blocklist + table-source-COPY bypass is a real, portable technique and is documented as a deviation — that framing is fine. The problem is solely BL-1 (the filter doesn't cover the whole injection surface).

## Everything else — green (for the fast re-review)
Intended exploit exit 0 (X-FCTUID table-source COPY → OOB exfil; flag == independent HMAC), checker solved. Posture PASS all 3 (app=app/10001, db=70:70, oob=app/10001; read_only, cap_drop:ALL, no-new-privileges, pids+mem; app loopback-only, db+oob NO host port; tmpfs incl /labflag). Flag hygiene: raw secret absent from db, no FLAG in tables, flag on db fs only, no baked flag (strict 0). Image 142.7 MB. trivy library=0 / os=0. gitleaks clean. drift-lint (22 impl, catalog reconciled: objective/flag_hint/tech_stack → real chain incl OOB sidecar). map, typecheck (5), format, dockerfile-pin (22), meta schema-valid (CWE-89+CWE-78). SOLUTION 9 H2 sections + 3 payload vectors + fix. hints 1-3 progressive. OOB collector sidecar (stdlib http.server, in-memory store, non-root, contained) — clean.

## Minor non-blocking note
- `/solve` (`app.py:163`) compares the flag with `==` rather than `hmac.compare_digest` (copy-program/moveit used constant-time). Negligible for a flag submit, but inconsistent — consider aligning while you're in there.

Genuinely strong lab otherwise — the OOB-collector-sidecar + dual-egress-drop containment is well done and I verified it end to end. Just close the IPS's blind spot and it's a PASS.
