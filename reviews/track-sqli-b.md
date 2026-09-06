# AUDITOR review — batch `track-sqli-b`

- **Branch / head:** `build/track-sqli-b` @ `bbd1efef9400418cb6d3280bf038a76d11e0f5cd`
- **PR:** #4 · **Base:** `main`
- **Labs (6):** `sqli-error-based-extractvalue` (apprentice), `sqli-time-blind-mysql-sleep`,
  `sqli-header-user-agent-analytics`, `sqli-limit-offset-postgres`,
  `sqli-waf-bypass-versioned-comments-mysql`, `sqli-waf-bypass-whitespace-tabs` (practitioner ×5)
- **Verdict:** **`pass_with_findings`** — one P1 (a factual error in student-facing teaching
  content) must be fixed for a clean `pass`; the P2s below are should-fix in the same revision.
  No security or solvability blocker: every security and functional gate passed hand-verification.

Everything below was **hand-run independently**, not read off CI or the request's evidence block.

## Dynamic gauntlet (serial, live Docker) — all 6 GREEN

| lab | build | image MB | baked `FLAG{` in image | posture (app + db) | exploit | wall-time | flag == HMAC | checker |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| error-based-extractvalue | ✓ | 159 | 0 | GREEN (`app`, `999`) | exit 0 | <1s | ✓ | PASS |
| time-blind-mysql-sleep | ✓ | 159 | 0 | GREEN (`app`, `999`) | exit 0 | 11s | ✓ | PASS |
| header-user-agent-analytics | ✓ | 159 | 0 | GREEN (`app`, `999`) | exit 0 | <1s | ✓ | PASS |
| limit-offset-postgres | ✓ | 179 | 0 | GREEN (`app`, `70`) | exit 0 | <1s | ✓ | PASS |
| waf-bypass-versioned-comments | ✓ | 159 | 0 | GREEN (`app`, `999`) | exit 0 | 1s | ✓ | PASS |
| waf-bypass-whitespace-tabs | ✓ | 159 | 0 | GREEN (`app`, `999`) | exit 0 | <1s | ✓ | PASS |

- **No baked flag** in any image (`docker export` of the un-started image → 0 hits on `FLAG{[0-9a-f]`).
  The flag is derived at runtime by `entrypoint.sh` (`hmac_sha256(LAB_USER_SECRET,"v1|"+slug)`, slug ==
  dir), written to a tmpfs, and the secret is `unset` before `exec` so the live app cannot re-derive it.
- **Posture gate** (`scripts/check-posture.sh <all cids>`) green on **both** containers of each lab:
  non-root app (`USER app` uid 10001), non-root DB (`999`/`70`), `read_only`, `cap_drop: ALL`,
  `no-new-privileges`, pids/mem limits, loopback-only ephemeral app port, DB publishes no host port,
  tmpfs datadirs at 0700.
- **Exploit correctness:** each `exploit.py` recovered the flag and it **matched a flag I derived
  independently** from the same secret; all well under the 60 s gate (time-blind 11 s with
  `POOL_WORKERS=4` against the `--workers 4` server — i.e. the *code* path is correct at 4).

## Trivy two-call gate (trivy 0.74.0, hand-run) — all 6 PASS

- App-dep gate (`--pkg-types library --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed`): **exit 0** ×6.
- OS gate (`--pkg-types os --severity CRITICAL --exit-code 1 --ignore-unfixed`): **exit 0** ×6.
- Pinned DB base images (`mysql:8.4`, `postgres:16-alpine`): **0** real unfixed OS CRITICAL.
- Matches my track-a ruling (app deps block on HIGH+, OS blocks on CRITICAL only).

## Repo-wide gates (hand-run)

`prettier --check .` clean · `pnpm run catalog` (12 implemented, schema-validated on build) ·
`pnpm run map` (541 nodes / 521 edges) · `pnpm -r lint` · `pnpm -r typecheck` ·
`check-dockerfiles.sh` (12/12 digest-pinned) all green. `gitleaks` is not installed on the audit
box; substituted a targeted secret-grep over the batch diff (baked `FLAG{`, `LAB_USER_SECRET=<value>`,
private keys, AWS keys) — **clean**.

## Static / pedagogy (6 parallel deep audits + my spot-checks)

- **Flag contract:** correct in all 6 (runtime HMAC, slug-matched, secret unset post-derive). No baked flag/secret.
- **Exploits are stdlib-only** (argparse/hashlib/hmac/json/os/re/sys/urllib[/time/concurrent.futures]); no `requests`/driver imports.
- **`sqli-header-user-agent-analytics` is genuinely second-order:** the write path binds the UA as a
  parameter (`INSERT ... VALUES (%s, NOW())`), and a *different* read path (`/admin/insights`)
  concatenates the re-read stored value into SQL. Not reflected — authentic.
- **Both WAF bypasses are real and honest (traced byte-by-byte):** the naive payload is genuinely
  blocked, the intended primitive genuinely evades the *same* filter and reaches the sink, and the
  `/waf-log` / `/debug` oracles report truthfully. Not for-show.
- **Documented deviations VALIDATED** — each is justified in the lab's `SOLUTION.md` **and** concurs
  with `docs/tracks/sqli.md`: (1) time-blind 16-hex `beacon_token` (vs catalog's aspirational 40) to
  fit the <60 s gate at the same cadence; (2) limit-offset scalar-subquery error oracle (Postgres
  grammar forbids `UNION` after `LIMIT`); (3) both WAF filters implemented in-app to stay
  single-container while preserving the identical bypass primitive.

## Findings

### P1 — `sqli-time-blind-mysql-sleep`: student docs state the wrong worker count (MUST fix for clean pass)
The lab's core lesson is "cap the client thread-pool to the server worker count." The **code is
correct at 4** (`entrypoint.sh:18` `--workers 4`; `exploit.py:73` `POOL_WORKERS = 4`), but the
**student-facing docs still say 2**:
- `SOLUTION.md:140` "The pool is capped at **2 workers on purpose**" and `:141` "the same number as
  the server's `gunicorn --workers 2`"
- `hints/3.md:25` "cap your concurrency at the number of server workers (2 here)"

A learner reasoning from the docs builds the wrong mental model of the exact concept the lab teaches.
The automated solve still passes (4 == 4), so this is not a solvability/security blocker — but it is a
factual error in graded teaching content and is a 3-line fix. **Change the two docs to `4`.**

### P2 — `max_lifetime_minutes` ≤ `estimated_minutes` on 4/6 labs (should fix)
A learner working at the estimated pace can be reaped mid-solve:
- header-user-agent: est **35**, lifetime **30** (life < est)
- time-blind: est **35**, lifetime **30** (life < est)
- limit-offset: est 30, lifetime 30 (no buffer)
- waf-whitespace-tabs: est 30, lifetime 30 (no buffer)

(error-based 25/30 and waf-versioned 28/30 are fine.) Looks like the template default (30) wasn't
raised for the longer practitioner labs. Raise `max_lifetime_minutes` to give real slack (e.g.
≥ `estimated_minutes` × 1.5, or a flat 60).

### P2 — `data/catalog.json` tech-stack drift is now systemic (should fix + operator decision)
All six catalog entries name a **different language** than shipped: Node/Express, Node/Fastify,
Ruby/Sinatra, Rust/axum/sqlx, PHP+ModSecurity/CRS, Go/Node/Caddy — all shipped as **Flask + MySQL/PG**.
`limit-offset`'s entry additionally misdescribes the *technique* and *objective* (UNION / "return admin
rows" vs the shipped error-oracle leaking `recovery_code`). `build-catalog.ts` neither merges `meta.json`
over `catalog.json` nor copies `tech_stack` into the generated/index artifacts, so `catalog.json`
silently contradicts reality for every implemented lab. This is the tech-stack-drift follow-up flagged
after track-a for *this* batch; it wasn't done.

Mitigation: the authoritative `docs/tracks/sqli.md` and each `SOLUTION.md` **do** state "Flask" and
disclose the deviations — so nothing user-facing is currently wrong, and this is not a merge blocker.
Two asks: (a) **should-fix** — reconcile `catalog.json` entries for implemented labs to the shipped
stack/technique, or add a `build-catalog` lint that fails when an implemented lab's `catalog.json`
`tech_stack` disagrees with its `meta.json`, so this can't drift again; (b) **operator decision** —
a *uniform re-platform of feasible labs to Flask* is now underway (track-a used 4 stacks; track-b uses
1). That trades the catalog's promised stack diversity for authoring speed/uniform hardening. It's a
product-direction call, not mine — surfacing it to the operator (separate from the pending
infeasible-labs charter item).

### P2/P3 — minor, `sqli-waf-bypass-whitespace-tabs`
- `README.md:53-57` names the exact bypass bytes (`/**/`, `%0a`, parens), pre-empting the progressive
  disclosure `hints/2.md` is meant to provide (and contradicting the README's own "reveal the hints"
  framing). Genericize in the README; keep specifics in the hints.
- Naming nit: the filter *strips* tabs (`%09`→tab→removed), so tabs are **blocked**, not the bypass;
  the real primitives are `/**/` and `%0a`. Docs are internally honest, but the slug/title can mislead.
- The "in-app filter vs separate WAF container" deviation is covered in substance but never stated in
  one explicit sentence in `SOLUTION.md`; add one line for parity with the versioned-comments lab.

## Explicitly checked and cleared (not findings)
- **Committed `.pyc`** (raised by the static pass): **false** — `git ls-files` shows 0 tracked
  `__pycache__`/`.pyc`; the dirs are on-disk build artifacts only.
- **`cryptography==50.0.0` "may not resolve"** (raised by the static pass): **false** — all six images
  built successfully; the pin resolves (and already shipped in track-a).
- **App service has no compose `user:`**: acceptable — non-root is enforced by the Dockerfile
  `USER app` (uid 10001) and confirmed live by the posture gate on every app container.

## Path to `pass`
Fix the P1 (time-blind worker-count docs → 4); ideally fold in the two P2 should-fixes (lifetimes;
catalog reconciliation/lint) in the same `-r1`. Re-review is fast — I only need to re-diff the changed
docs/meta and rebuild `sqli-time-blind-mysql-sleep` once. The catalog *re-platform product decision* is
for the operator and does not gate this batch.
