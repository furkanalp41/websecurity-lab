# Review — `track-sqli-a-r1` (re-review)

- **Reviewer:** denetle (AUDITOR)
- **Reviewed commit:** `afd69e0569f1ae42ed65df615777ab23818c5854` (atop merged r0 review)
- **Prior:** `reviews/track-sqli-a.md` — `pass_with_findings` on `60d3de9`
- **Verdict:** ✅ **`pass`**

Both `must_fix` and the `nice_to_have` verified. Because r1 bumped dependencies (some substantially), I **rebuilt and re-ran every dependency-changed lab** rather than trusting CI.

## must_fix — verified closed

**MF-S1 — trivy app-dependency gate** — implemented exactly as ruled: (1) `--severity HIGH,CRITICAL --pkg-types library --exit-code 1`, (2) `--severity CRITICAL --pkg-types os --exit-code 1`, (3) HIGH+CRITICAL advisory (exit 0). All library HIGHs were cleared by real fixed-version bumps (no `.trivyignore`): cryptography 46→50, Go build image 1.24→1.25 (go1.25.14), FastAPI 0.115→0.141.1 (+ starlette 1.6.0 / uvicorn / asyncpg). The gate is fail-closed on author-controlled deps and pragmatic on base-OS lag — correct. ✅

**MF-S2 — go.sum** — `sqli-cookie-tracking-id/src/go.sum` is now committed; the Dockerfile drops `GOSUMDB=off` and `GOFLAGS=-mod=mod`. **Verified live:** the lab rebuilds cleanly under default `-mod=readonly` (checksums enforced) and the exploit still lands the flag. ✅

## nice_to_have — verified

**NTH-S1** — both practitioner labs now split the ladder: hint 3 = payload *shape* (binary-search method / UNION structure) with an explicit pointer to hint 4; hint 4 = exact payload + full request flow. Gradient no longer leapfrogs. ✅

## Regression re-verification (rebuilt the 3 bumped labs)

| Lab | Bump | Rebuild | Posture | Exploit | Flag |
|---|---|---|---|---|---|
| boolean-blind | FastAPI 0.115→0.141.1 + starlette 1.6.0 (major) | ✅ | app / `70:70` | 0.65s | ✅ — X-Account-Exists header oracle still returns `false`/`true` correctly |
| union | cryptography 46→50 | ✅ | app / `999:999` | landed | ✅ |
| cookie | golang 1.25 + go.sum | ✅ (checksum-verified build) | app | landed | ✅ |

The risky one — the starlette 1.x jump under boolean-blind — did **not** break the oracle. order-by and second-order had no dependency change (second-order only got the hint split), so they carry their r0 verification.

## One trivial follow-up (not blocking)

- **tech_stack drift:** `sqli-boolean-blind-account-enum` `meta.json` (and the authoritative `catalog.json`) still say `"FastAPI 0.115"` while it now ships `0.141.1`. Descriptive-only, doesn't affect the lab. Sweep the label to match (or genericize to `"FastAPI"`) in a future batch — **AUDITOR-approved** as a minor catalog tweak, same as the Django-patch spirit. Not a merge blocker.

## Disposition

`track-sqli-a` is cleared to merge to `main`. This completes the first track pilot and establishes the multi-service hardened-non-root-DB + two-call-trivy pattern for the remaining tracks. Next batch per the operator's sequencing; the Q2 re-platform ruling (Windows/Oracle/Elasticsearch labs) is still the one operator decision outstanding before those specific labs are authored.
