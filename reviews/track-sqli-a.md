# Review — `track-sqli-a`

- **Reviewer:** denetle (AUDITOR)
- **Reviewed commit:** `60d3de9ddbb54942f46f344dffce1b522c9c920b` (`build/track-sqli-a`, 4 commits atop `main` `fcd52cf`)
- **PR:** https://github.com/furkanalp41/websecurity-lab/pull/3
- **Verdict:** `pass_with_findings` — 2 `must_fix` (both cheap; neither breaks a lab), 1 `nice_to_have`. The 5 labs are functionally excellent and fully hand-verified.

Every lab was **built and hand-run locally, serially** (build → posture on *every* container → exploit → unintended-path probe → teardown), staying within the freed disk headroom. Not read off the evidence.

## Per-lab verification (all ✅)

| Lab | Stack | Posture (app / db) | Exploit | Flag=HMAC | Gating |
|---|---|---|---|---|---|
| sqli-order-by-numeric | Flask+Postgres | `app` / `70:70` | 0.13s | ✅ | `/solve?user=` needs leaked `current_user`; `/flag.txt` 404, `/solve` 403 |
| sqli-union-product-search | Flask+MySQL | `app` / `999:999` | 0.10s | ✅ | `/solve?token=` needs `admin_notes.secret`; 403 otherwise |
| sqli-cookie-tracking-id | Go+SQLite | `app` (24MB img) | 0.10s | ✅ | `/solve?license=` needs `internal_config.license_key`; 402 otherwise; no baked flag |
| sqli-boolean-blind-account-enum | FastAPI+Postgres | `app` / `70:70` | 0.67s | ✅ | `/solve` needs recovered `password_hash` prefix |
| sqli-second-order-registration | Django+Postgres | `app` / `70:70` | 0.42s | ✅ | `/solve?secret=` needs `session_secret`; Django patched to 5.1.14 |

**Multi-container posture gate works live** — `check-posture.sh` now asserts non-root/Privileged=false/ReadonlyRootfs/CapDrop ALL/no-new-privileges/pids+mem/loopback on *both* app and DB, and every DB runs non-root (hardened Postgres `70:70` with tmpfs PGDATA at `0700`; MySQL `999:999`), no DB host port published, per-lab bridge. This is exactly the pattern the tracks need.

**Also verified:** all 6 metas schema+enum valid (CWE-204/208/209 present); all Dockerfiles digest-pinned incl. multi-stage; all non-root `USER`; no baked flag; all `exploit.py` stdlib-only; every `SOLUTION.md` covers the 8 merged section intents; READMEs have all 3 required sections and no solution spoilers (the order-by README's `' OR '1'='1'` mention is the intentional "why tautologies fail here" teaching point); hint ladders progressive and ≤400w; no `__pycache__`/`.pyc` tracked. CI fixes are sound — the `grep '^websec-lab/'` image-resolution fix correctly scans the built app image (not the pulled DB), and the posture step passes all container ids.

## `must_fix`

### MF-S1 — Trivy gate: keep CRITICAL-gate + base-OS HIGH-advisory, but ALSO gate app-dependency HIGHs (security-posture) — *this is my ruling on Q1*
Your CRITICAL-fail + HIGH-advisory change is **accepted for base-OS / language-stdlib HIGHs** — those genuinely lag upstream base rebuilds, are tracked (advisory group + weekly-drift + base-digest bot), and shouldn't block a batch for deliberately-vulnerable, hardened, loopback-only, auto-reaped containers. Fail-closed doesn't require chasing base-image lag.

**But the gate must also fail on a fixed HIGH in the lab's OWN application/library packages** (`--pkg-types library`), not just CRITICAL. Those deps are author-chosen and pinned, trivially bumpable (exactly as you did for `cryptography` 44→46 and Django), and a HIGH in a framework the lab ships can hand learners an *unintended* solve path or mask the intended bug. So: fail on any fixed CRITICAL (any pkg-type) **OR** any fixed HIGH in `--pkg-types library`; advisory-only for fixed HIGH in `--pkg-types os`. One extra trivy call:
```
trivy image --severity HIGH,CRITICAL --pkg-types library --ignore-unfixed --exit-code 1 <img>   # app deps: HIGH+ blocks
trivy image --severity CRITICAL       --ignore-unfixed --exit-code 1 <img>                        # OS: only CRITICAL blocks
```
This is fail-closed on the half you control and pragmatic on the half you don't. Not an escalation — implement in r1.

### MF-S2 — `sqli-cookie-tracking-id` builds without checksum verification (supply-chain) — *Q3, go.sum*
The Go Dockerfile sets `GOFLAGS=-mod=mod` **and** `GOSUMDB=off` and ships **no `go.sum`**, so modules (`chi`, `go-sqlite3`) are fetched with **no integrity verification**. Versions are pinned in `go.mod`, so this is unverified-checksum/non-reproducible rather than fully-floating — but `GOSUMDB=off` + no `go.sum` is precisely the anti-pattern a security platform (with a `track-supply-chain` on the roadmap) must not model, and it's the template every future Go lab will copy. **Fix:** `go mod tidy` to generate & commit `go.sum`, then drop `GOSUMDB=off` and `GOFLAGS=-mod=mod` (default `-mod=readonly` + `go.sum` verifies on build). Cheap, and sets the correct Go pattern once.

## `nice_to_have`

- **NTH-S1 (pedagogy):** on the two **practitioner** labs, hint 3 already gives the *exact* payload string + full step-by-step flow — that's hint-4 / near-solution territory per the ladder spec (hint 3 = payload *shape/structure*, optional hint 4 = near-solution). Consider splitting on practitioner+ labs (3 = shape, 4 = full payload) so the gradient doesn't leapfrog. Apprentice labs are fine as-is. (Pedagogy call — yours to weigh.)

## Answers to your questions

- **Q1 (trivy):** ruled above → **MF-S1** (accept CRITICAL-gate + OS-HIGH-advisory; add an app-dependency HIGH gate).
- **Q2 (re-platform infeasible labs):** **defer to the operator — accepted as `coverage_gaps` for this batch** (none of those labs ship here, so nothing is blocked). My standing recommendation to the operator: **Bucket 1** (Fortinet/MoVEit — no containerizable product) → abstract the vuln class onto a Linux stack per charter §13; **Bucket 2** (MSSQL/Oracle/Elasticsearch — these *do* have Linux images, so the real blocker is the ≤300 MB / 512 MB / ≤60 s caps, not the OS) → operator picks a documented `resource_tier: heavy` exception vs. abstraction. The operator must rule before those specific labs are authored; not a `track-sqli-a` blocker.
- **Q3 (nginx/Caddy + go.sum):** omitting the reverse proxies is **fine** — the metas don't list them, they add nothing to a SQLi lab, and each SOLUTION notes it. `go.sum` is **not** optional → **MF-S2**.

## Disposition

Close MF-S1 and MF-S2 on `build/track-sqli-a`, re-send as `track-sqli-a-r1`. Both are small and neither touches a lab's functionality — the 5 labs themselves are cleared on the merits. NTH-S1 and the Q2 charter call can ride along or be scheduled. Excellent first track; the multi-service hardened-DB pattern is a strong foundation for the remaining tracks.
