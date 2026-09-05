# CLAUDE.md — WebSecurity Lab

Project-level instructions for every Claude session and subagent that works in this repo.
**Read `docs/two-session-protocol.md` before any batch.**

> **Working directory reality:** this project lives at `/home/vlad/websecurity-lab`.
> The original brief said `/home/vlad/newlab`, but that directory was already occupied
> by an unrelated, live, uncommitted project ("tallreel"). Per operator decision the
> build was relocated here. Wherever a companion doc says `/home/vlad/newlab`, read it
> as `/home/vlad/websecurity-lab`. GitHub remote: `furkanalp41/websecurity-lab`.

## Mission

Build a **self-hosted, Docker-first, gamified web-security CTF platform** that is better
than PortSwigger Web Security Academy and covers every web vulnerability class seen on
HackerOne / YesWeHack / Intigriti / CTFtime / public CVEs (2022–2026). Users clone the
repo and run `./labctl serve` — no VPS, no hosted infra, no cost. Every lab runs in its
own isolated Docker container. The UI is a Matrix-themed hub where a Rive rabbit chases a
golden carrot up a skill map; the final track is a **Report Studio** that trains
bug-bounty report writing against an adversarial-triager simulator. Take a complete
beginner and turn them into someone who can file a valid HackerOne report.

## Non-goals (do NOT do these)

- No VPS, no public lab hosting, no paid cloud infra. Labs run locally in the learner's Docker.
- No reproduction of proprietary target code. Abstract the vuln class; cite reports/CVEs only in `inspired_by`.
- No real PII / scraped data / real customer domains. Seed data is Faker with a fixed seed.
- No `--privileged`, no `/var/run/docker.sock` mount, no `--net=host` / `--pid=host` / `--ipc=host`
  unless a lab's charter explicitly justifies it AND it is gated behind `risk: elevated` + a red confirm.
- No streaks, no 🔥 flame glyphs, no streak notifications, no default-on global leaderboards,
  no XP-purchase / hint paywalls / premium tiers. Free labs, free hints, free solutions forever.
- No telemetry on by default.
- Never bake `FLAG{...}` into an image. Per-container flag is written at runtime by `entrypoint.sh`.
- Do not invent labs. `data/catalog.json` (541 labs) is authoritative; deviations need an AUDITOR-approved charter update.

## Tech stack (fixed decisions — do not re-litigate)

- **Hub**: Next.js 15 App Router + React 19, static-exportable (`output: 'export'` when `NEXT_STATIC=1`).
- **Styling**: Tailwind 4 + CSS custom-property design tokens from `docs/ux-hub-spec.json`. Matrix-dark only.
- **UI primitives**: shadcn/ui (Radix) + 21st.dev (see `docs/ux-components.md`). Motion: Framer Motion; rabbit: Rive.
- **Language**: TypeScript strict everywhere (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`,
  `noImplicitOverride`, `noFallthroughCasesInSwitch`, `noImplicitReturns`). No `any` without a documented reason.
- **Runtime**: Node 24 LTS (pinned in `.nvmrc`, `packageManager`, CI). **Package manager**: pnpm 9 workspaces
  (`hub`, `labctl`, `packages/*`).
- **Containers**: Docker Engine 25+ / Compose v2. Lab bases digest-pinned; CI fails on unpinned `FROM`.
- **CI**: GitHub Actions — lint + typecheck + schema-validate + hub-build + per-lab docker matrix + trivy + dive + gitleaks.
- **Format/lint**: ESLint + Prettier (100-col, semicolons on, single quotes, trailing commas).

## Repo layout

```
data/catalog.json          541 lab specs (authoritative)  ·  data/*.generated.json (built, gitignored)
labs/<track>/<slug>/        one self-contained lab (see quality bar below)
hub/                        Next.js 15 App Router (matrix theme, level map, report studio)
labctl/                     Node 24 TS CLI + WS daemon (127.0.0.1:5174, bearer token, origin allowlist)
packages/schema             canonical OWASP + CWE enums, meta schema re-export
packages/eslint-config-websec-lab   shared ESLint config
packages/exploit-runtime    shared Python exploit runtime reference (stdlib + requests)
scripts/                    build-catalog.ts, build-map.ts, bootstrap.sh
docs/                       architecture.json, ux-hub-spec.json, collab-protocol.json, two-session-protocol.md,
                            reviews/{completeness,docker-security,education}.json, tracks/
handoffs/                   BUILDER batch-review-request payloads
ESCALATIONS.md              jointly-edited human escalations
```

## Two-session collaboration

- **newlab** (BUILDER) builds; **denetle** (AUDITOR, Opus 5, 1M) reviews. Both load
  `docs/two-session-protocol.md` before any batch.
- Every batch ships on `build/<batch_id>`, one branch per batch, ≤20 labs per batch, one batch in flight at a time.
- BUILDER opens a PR, runs local CI green, captures `self_test_evidence`, then
  `SendMessage({to: "denetle", ...})` with the full `batch-review-request` JSON.
- Do not merge without an AUDITOR `verdict: "pass"` on the exact head commit reviewed.
  `pass_with_findings` → fix every `must_fix` on the same branch, re-send as `<batch_id>-r1`.
- See `PROMPT-1-BUILDER-newlab.md` / `PROMPT-2-AUDITOR-denetle.md` in the kickoff pack for full role prompts.

## Commit / PR rules

- Conventional Commits. Every commit message ends with:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_017EiGtUoTq35eEc4vsSuBMB
  ```
- Every PR description ends with: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- PR title: `[<batch_id>] <short summary>`. PR per batch, never per lab.

## Per-lab quality bar (all seven artifact groups, non-negotiable)

- `meta.json` — schema-valid (`labctl/src/schemas/meta.schema.json` v1.0.0); unique `id`; correct `track`;
  truthful `difficulty` (`apprentice|practitioner|expert|elite`).
- `README.md` — `## Scenario`, `## Objective`, `## Getting Started`; names a CVE-analog family, no payload/spoiler.
- `SOLUTION.md` — merged 8 section intents: `## What tipped you off`, `## The class of bug`,
  `## Why the developer wrote it this way`, `## The mechanical exploit` **plus**
  `## Vulnerability`, `## Why it exists`, `## Exploit walkthrough`, `## Fix`.
- `hints/1.md`,`2.md`,`3.md` (+optional `4.md`) — progressive Socratic ladder, ≤400 words each, free (no XP cost).
- `Dockerfile` — `FROM …@sha256:<64-hex>` digest-pinned, non-root `USER` before final CMD, no baked flag,
  <300 MB image.
- `docker-compose.yml` — `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`,
  `mem_limit`/`cpus`/`pids_limit`/`ulimits`, healthcheck, capped logging, port publishes exactly one
  `127.0.0.1:${LAB_HOST_PORT}:<port>`. No docker.sock, no privileged, no host net/pid/ipc.
- `tests/checker.sh` (`sh -eux`, exits 0 on solved) + `tests/exploit.py` (stdlib + `requests`/`httpx`,
  prints flag on last stdout line, <60 s in CI, reads `--target`/`--timeout`, secret from `LAB_USER_SECRET`).

Flag contract: `FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|" + slug) }`. CI dev secret is 64 zeros; never hardcode it.

## Known issues / decisions to carry forward

- **Duplicate slugs in the authoritative catalog** (must be uniqued via charter update before those tracks ship):
  `graphql-batch-auth-bypass` (graphql-api-owasp-top10 ↔ ctftime-web-2024-2026) and
  `nginx-alias-off-by-slash` (smuggling-cache-desync ↔ command-injection-upload-fileread).
- **Spec conflict**: `docs/ux-hub-spec.json` details daily streaks / 🔥 flame / default leaderboards, which
  PROMPT-1 §13 forbids. Non-goals win. Resolve at P2 (gamification) via charter/escalation.
- **Category names**: directories use the `data/catalog.json` category slugs (`sqli`, `xss`, …), not the
  `web-*` names in an early `docs/architecture.json` draft. The catalog is authoritative.
- **Sample-lab port**: Apache listens on 8080 (non-privileged) so the container runs non-root + `cap_drop: ALL`
  without `NET_BIND_SERVICE`. Lab networks are per-lab bridges (not `internal: true`, which breaks host port publishing).
- The flag-in-context check matches a _materialized_ flag literal `FLAG\{[0-9a-f]{64}\}` (not the `FLAG{` prefix in
  `entrypoint.sh` derivation code), and always allows `SOLUTION.md` and `tests/`.

## Startup steps for a new session

1. `gh repo view furkanalp41/websecurity-lab`. 2. `ListAgents` → confirm `denetle` reachable.
2. Read `docs/two-session-protocol.md` + the relevant `docs/reviews/*.json`. 4. `node --version` must be v24.x
   (`nvm use 24`); pnpm 9 via corepack. 5. Work the current batch only; never start the next while one is in review.
