# Review — `arch-000` (P0 bootstrap)

- **Reviewer:** denetle (AUDITOR, Opus, 1M)
- **Reviewed commit:** `405fa79a8d0021c9a96e8f7b5c9e857f8f936a02` (`build/arch-000`, 5 commits ahead of `main`)
- **PR:** https://github.com/furkanalp41/websecurity-lab/pull/1
- **Verdict:** `pass_with_findings` — 3 `must_fix`, 5 `nice_to_have`. No `fail`. The one reference lab is exemplary and fully hardened; the findings are about the **CI guardrails the scaffold must enforce for the 541 labs that follow**, not about anything shipped-broken.

Everything below was **independently reproduced locally** (Docker build+run, exploit, `docker inspect`, schema fuzzing, catalog/map builders, labctl typecheck+tests) — not read off the self-test evidence.

---

## 1. What I verified (evidence)

### Reference lab — `labs/sqli/sqli-login-bypass-basic`

| Check | Method | Result |
|---|---|---|
| Builds & healthy | `docker compose up -d --build --wait` (`LAB_USER_SECRET`=64×`0`, `LAB_HOST_PORT`=51000) | ✅ container `Healthy` |
| Intended exploit lands flag | `tests/exploit.py --target … --timeout 60` | ✅ **0.21 s**, exit 0 |
| Flag correctness | recovered flag == `hmac_sha256(secret,"v1\|slug")` | ✅ `FLAG{22dec2b2…4ebd}` matches |
| checker.sh | `tests/checker.sh <url>` | ✅ `checker: solved`, exit 0 |
| Runtime posture | `docker inspect` on the running container | ✅ `User=app` (uid 10001), `Privileged=false`, `ReadonlyRootfs=true`, `CapDrop=[ALL]`, `CapAdd=<none>`, `SecurityOpt=[no-new-privileges:true]`, `PidsLimit=100`, `Memory=MemSwap=512m` (swap off), `NanoCpus=1e9`, port bound **`127.0.0.1:51000` only** |
| Non-root confirmed | `docker exec … id` | ✅ `uid=10001(app) gid=10001(app)` |
| Read-only rootfs enforced | `docker exec … 'echo x > /var/www/html/pwn.txt'` | ✅ `Read-only file system` (write blocked); `/tmp` tmpfs writable |
| No baked flag | `docker create` + `docker export \| grep -aE 'FLAG\{[0-9a-f]{64}\}'` | ✅ none (flag written at runtime to tmpfs) |
| Image size | `docker image inspect --format {{.Size}}` | ✅ **27 MB** (cap 300) |
| Layer history clean | `docker history --no-trunc` | ✅ no flag/secret/user.key |
| SOLUTION/hints/tests excluded from image | `docker export \| tar -t` | ✅ absent (`.dockerignore` works; only Alpine's own `etc/profile.d/README` present) |

### Adversarial / unintended paths (tried to break gating — all held)

- `GET /admin/dashboard` with **no session** → `302 → /admin/login`, **no flag**. ✅
- Direct fetch of flag/db/lib: `/flag.txt`, `/var/lib/lab/flag.txt`, `/app.db`, `/lib/db.php`, `%00`/`..%2f` traversals → **all 404** (flag & lib live outside DocumentRoot). ✅
- Tautology variant `x' OR role='admin'-- -` also solves — an acceptable alternate path (still requires the SQLi), noted in SOLUTION.md. ✅
- No unauthenticated read of the flag exists; the SQLi is the only door. ✅

### Toolchain / scaffold

- `scripts/build-catalog.ts`: **541 labs / 20 categories**, 1 lab discovered & schema-valid, dir==track==catalog-category cross-check works, enum membership enforced. Exit 0. Both known duplicate slugs **warn** (don't fail) as designed.
- `scripts/build-map.ts`: 539 nodes / 519 edges — math consistent (541 − 2 dup slugs = 539 nodes; 539 − 20 tracks = 519 linear edges). sha256 sidecar written. Exit 0.
- **Meta-schema strictness — 18-case fuzz against the real schema+enums:** every malformed input rejected (missing required, bad `difficulty`/`track` enums, `additionalProperties`, bad OWASP/CWE patterns, `risk:elevated` w/o `elevated_caps`, uppercase `id`, out-of-range `estimated_minutes`, short `title`/`flag_hint`, <2 `learning_objectives`, empty arrays, wrong `schema_version` const). Only nuance: `A99:2021-Nonsense` passes the **schema** (pattern-only) but is caught by build-catalog's **enum** check — defense-in-depth, fine.
- `labctl` typecheck: OK. `labctl` unit tests (flag vector): 2/2 pass.
- Flag HMAC contract is **consistent across all four sites**: `flag.ts` (`createHmac(sha256,secret).update("v1|"+slug)`), `entrypoint.sh` (`hash_hmac("sha256","v1|slug",secret)`), `exploit.py` (`hmac.new(secret,"v1|slug",sha256)`), and `flag.test.ts` vector. `verifyFlag` uses `timingSafeEqual`.
- No build artifacts tracked in git (`.next/`, `out/`, `*.generated.json`, `__pycache__` all gitignored & untracked). Commit trailers correct. `main` is an ancestor of `build/arch-000` — clean merge, no regression risk.

---

## 2. `must_fix`

### MF-1 — CI has **no runtime posture gate** (security-posture) 🔴
`.github/workflows/ci.yml` `docker-lab-matrix` (lines 101–152) never runs `docker inspect` to assert the security baseline. Its only `inspect` call is for **image size** (line 119). I confirmed by grep: no `Privileged` / `ReadonlyRootfs` / `CapDrop` / `no-new-privileges` / non-root `User` / port-binding assertion anywhere in CI, and no helper in `scripts/`.

**Impact:** a future lab shipped as **root**, or without `cap_drop: ALL`, or with `read_only:false`, or bound to `0.0.0.0` instead of `127.0.0.1`, would pass CI green. This is precisely the guarantee arch-000 exists to lock in, and Phase-0 explicitly lists a **"docker inspect posture baseline script"** as a deliverable — it is absent (`scripts/` has only `bootstrap.sh`, `build-catalog.ts`, `build-map.ts`). Fail-closed tie-breaker (protocol §Tie-Breakers.1) applies.

**Suggested fix:** add `scripts/check-posture.sh <container>` asserting `User∉{"",0,root}`, `Privileged=false`, `ReadonlyRootfs=true`, `CapDrop⊇[ALL]` (or charter-justified `risk:elevated`), `SecurityOpt` contains `no-new-privileges:true`, non-empty `PidsLimit`/`Memory`, and every published port bound to `127.0.0.1`. Call it in `docker-lab-matrix` right after `compose up --wait`; fail the job on any deviation. (The sample lab already passes all of these — this just makes CI enforce it.)

### MF-2 — CI does **not enforce digest-pinned `FROM`** (security-posture) 🔴
CLAUDE.md (Tech stack) states *"Lab bases digest-pinned; CI fails on unpinned `FROM`."* No such check exists. An unpinned `FROM alpine:3.20` (no `@sha256:…`) would build and pass.

**Suggested fix:** a lint step that fails unless **every** `FROM` line in `labs/**/Dockerfile` matches `^FROM \S+@sha256:[0-9a-f]{64}` (multi-stage: each `FROM` must be pinned; allow `FROM <stage-alias>` back-references). Cheap, static, no Docker needed.

### MF-3 — Hub TS config diverges from the mandated "strict everywhere" baseline (config) 🟠
`hub/tsconfig.json` sets only `"strict": true` and does **not** extend `tsconfig.base.json`, so it silently omits every extra flag CLAUDE.md lists as a fixed decision: `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `noFallthroughCasesInSwitch`, `noImplicitReturns`, `noUnusedLocals`, `noUnusedParameters`. arch-000 is the one place to set this before real UI code lands and inherits the weaker config.

**Suggested fix:** add those seven `compilerOptions` explicitly to `hub/tsconfig.json` (can't blindly `extends` base because Next needs its own `module`/`moduleResolution:bundler`/`jsx:preserve`, but the strictness flags compose fine). `labctl` and `packages/schema` already extend base correctly — hub is the only gap.

---

## 3. `nice_to_have`

- **NTH-1 (hub/copy):** `hub/app/page.tsx:5` says *"Two hundred labs. One rabbit. One carrot."* while `layout.tsx`, `/map`, and `README` say **541** (and `docs/architecture.json` says "200+"). Align the landing copy to 541.
- **NTH-2 (ci):** once Q4's slugs are uniqued, **flip `build-catalog`'s duplicate-slug `console.warn` to a hard error** so a re-introduced dup fails CI. (Correct to warn *today*, since the dups still exist in the authoritative catalog.)
- **NTH-3 (docs):** difficulty-tier vocabulary mismatch — schema/CLAUDE.md use `apprentice|practitioner|expert|elite`, but `docs/collab-protocol.json` `quality_gates` #7 uses `easy|medium|hard|expert` with time ceilings, so the AUDITOR "cold-attempt" ceilings don't map to the real tiers. Define ceilings for the actual four tiers (proposal: apprentice ≤10 min, practitioner ≤30, expert ≤90, elite ≤180) so difficulty audits are well-defined. (sqli lab @ "apprentice, 20 min" is fine under this.)
- **NTH-4 (daemon):** `labctl/src/daemon/server.ts` `verifyClient` rejects any WS client **without** an `Origin` header (good for the browser hub, but a future non-browser `labctl` WS client will need an exemption). Note for `ui-phase-2-lab-runner`.
- **NTH-5 (template hardening):** `LAB_USER_SECRET` remains in the container env post-exploit (confirmed via `docker exec … env`). Inert for SQLi, but for the **file-read / command-injection / XXE / deserialization-RCE / SSTI** tracks, any read primitive lets a learner recover the secret (→ recompute the flag) or read the flag file directly, bypassing the intended objective. Because this lab **is** the `new-lab` template, hardening it here propagates everywhere: in `entrypoint.sh`, after writing the flag, drop the secret before handing off — `export FLAG=…; unset LAB_USER_SECRET; exec httpd …` (or write flag then re-exec without the var). Not exploitable in this lab, so `nice_to_have`; the file-read-class tracks will still need per-lab flag placement outside the app's read scope.

---

## 4. Answers to the five questions

**Q1 — 20 category directory names OK for P1?** **Yes, confirmed.** The 20 track enum values, the 20 `data/catalog.json` categories, and the on-disk dir all agree, and build-catalog enforces the three-way match. (Separately, your own `docs/reviews/completeness.json` flags *missing* dedicated Information-Disclosure and Path-Traversal/LFI tracks — that's a future-charter coverage question, not a P1 blocker for the names as defined.)

**Q2 — static PNG rabbit placeholder OK for P0/P1, real `.riv` at polish-final?** **Yes.** P0 ships **no** rabbit asset at all (a text logotype `>_rabbit` in the top-bar), which is fine for the shell; a static PNG at P1 and the Rive `.riv` deferred to polish-final is the right sequencing. No blocker.

**Q3 — `sqli-login-bypass-basic` as the `new-lab` template exemplar?** **Approved.** All seven artifact groups present, fully hardened (verified by `docker inspect`), exploit 0.21 s, per-container gated flag, `SOLUTION.md` carries all eight merged WHY-section intents (not a payload dump), hints ladder is progressive and non-spoiler. Only ask: fold **NTH-5** into the template `entrypoint.sh` so every generated lab inherits the secret-drop.

**Q4 — two duplicate slugs, how to unique via charter update?** **AUDITOR-approved to unique them now** (edit to `data/catalog.json`, BUILDER-owned), before any of the four affected tracks ship — none are in P0. They are genuinely distinct labs, so keep both and rename:

| Track | Current slug | Title | → New slug |
|---|---|---|---|
| `smuggling-cache-desync` | `nginx-alias-off-by-slash` | "Nginx alias Traversal: The Missing Slash" (apprentice) | **`nginx-alias-traversal-basic`** |
| `command-injection-upload-fileread` | `nginx-alias-off-by-slash` | "Nginx Alias Off-by-Slash Directory Traversal" (practitioner) | **`nginx-alias-fileread-chain`** |
| `graphql-api-owasp-top10` | `graphql-batch-auth-bypass` | "Batching Past the Rate Limiter" (practitioner) | **`graphql-batch-rate-limit-bypass`** |
| `ctftime-web-2024-2026` | `graphql-batch-auth-bypass` | "GraphQL Batching to Skip Rate Limits and Auth" (practitioner) | **`graphql-batch-auth-bypass-ctf`** |

Do it as one standalone catalog-charter commit before the first of those tracks starts, then apply **NTH-2** (warn→error).

**Q5 — `docs/ux-hub-spec.json` streaks/flame/leaderboard vs Non-goals?** **Non-goals win; no escalation needed now.** CLAUDE.md Non-goals is an already-decided charter policy, so there is no live disagreement to escalate — the spec doc is simply stale. Nuance: the ux-hub-spec leaderboard is explicitly **"Local"** (opt-in, resettable), which the Non-goals *permit* (they forbid only *default-on **global*** leaderboards) — keep it. The true conflicts are **streaks (Ember/Blaze/Wildfire/Supernova), the `🔥` flame glyph, the daily-solve tracker, and streak milestone toasts** — drop those. **Action:** BUILDER annotate the affected `ux-hub-spec.json` sections now with an inline `SUPERSEDED by CLAUDE.md Non-goals — do not implement at P2` note so a future `ui-phase-3` session doesn't build them. Open a formal escalation only if, at P2, someone proposes reintroducing streaks (then it's a live charter-change request for the operator).

---

## 5. Verdict

`pass_with_findings`. Close MF-1..MF-3 on `build/arch-000`, re-send as `arch-000-r1`. MF-1/MF-2 are security-posture (fail-closed); MF-3 is a foundational config contract. The sample lab itself needs no changes to pass — it already satisfies every posture assertion MF-1 would add. `nice_to_have` and the Q4/Q5 charter actions can ride along in r1 or be scheduled explicitly.
