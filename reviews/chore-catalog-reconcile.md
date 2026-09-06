# AUDITOR review — batch `chore-catalog-reconcile`

- **Branch / head:** `build/chore-catalog-reconcile` @ `2037a9ab0b753cfe94f64f5028ca75c865f699c9`
- **PR:** #5 · **Base:** `main` @ `867ceca`
- **Verdict:** **`pass`** — cleared to merge; merging also greens `main` (the only red job was `secret-scan`/gitleaks).

Docs/data/tooling batch enacting the operator's Hybrid re-platform ruling + a red-main gitleaks fix.
All checks hand-run.

## Scope proof
`867ceca` (main) is an ancestor of `2037a9a`. Diff is **5 files**: `.gitleaksignore`, `CHANGELOG.md`,
`data/catalog.json`, `scripts/build-catalog.ts`, `labs/sqli/sqli-error-based-extractvalue/SOLUTION.md`.
**Zero** changes to any lab `src/`, `entrypoint.sh`, `Dockerfile`, `docker-compose.yml`, `tests/`,
`requirements.txt`, or `hints/`. So the 6 track-sqli-b images and every functional/security gate carry
forward unchanged; this review focuses on the security-gate change, the tooling, and the metadata.

## Security-critical: gitleaks fix (fail-closed verified)
Installed real gitleaks 8.21.2 (CI uses the `zricethezav/gitleaks` container, default ruleset, which
auto-reads `.gitleaksignore` — my run matches).

- **With `.gitleaksignore` (CI behaviour):** 29 commits scanned, **no leaks, exit 0.** Greens main.
- **With `.gitleaksignore` moved aside:** **exactly 2** findings, both `generic-api-key` at
  `sqli-error-based-extractvalue/SOLUTION.md:135` in the two immutable merged commits (`867ceca`,
  `bbd1efe`) — and **nothing else** anywhere in history.
- **`.gitleaksignore` is maximally precise:** two exact `commit:file:rule:line` fingerprints for that
  one benign finding. No path globs, no rule disabling, no wildcards. A real secret at any other
  file/line/commit — or at that line in any future commit — is still caught. **Nothing real is masked.**
- **Root-cause fix at HEAD:** `SOLUTION.md:135` `{"key":"<made-up-uuid>"}` → `{"key":"<the api_key you
  reassembled above>"}` (removes the entropy trigger, reads clearer). The UUID is immutable in merged
  history, which is why the two historical fingerprints are (correctly) suppressed rather than rewritten.

This is the right approach: prevention at HEAD + surgical suppression of un-rewritable history.

## Tooling: drift-lint (`scripts/build-catalog.ts`) — adversarially verified
Enforces the Hybrid guardrail: an implemented lab whose `data/catalog.json` `tech_stack` != its
`meta.json` `tech_stack` fails the build (exact array equality; unbuilt catalog entries exempt).

- Reconciled tree → `pnpm run catalog` **exit 0** (all 12 implemented labs match).
- I injected a bogus `tech_stack` element on `sqli-time-blind-mysql-sleep` → build printed
  `ERROR ... tech_stack drift vs data/catalog.json ...`, **refused to write** the generated files, and
  **exit 1**. Reverted → green again. The guardrail works and is fail-closed.

## Metadata: catalog reconcile
- All 12 implemented labs' `catalog.json` `tech_stack` now equals their shipped `meta.json` (track-a
  stays diverse: Go/FastAPI/Django/PHP/Flask; the 6 track-b labs = Flask) — enforced by the lint above.
- `sqli-limit-offset-postgres` description+objective corrected: was "post-LIMIT UNION / returns admin
  rows"; now the shipped scalar-subquery **error oracle** leaking `admin.recovery_code`. Matches the
  lab, `SOLUTION.md`, and `docs/tracks/sqli.md`.
- Regenerated `data/catalog.generated.json` / `hub/public/labs-index.json` are byte-identical to a fresh
  build (tree clean after regen). `prettier`, `map`, `typecheck` all green.

## Findings
- **Minor (pre-existing, not introduced here):** the CI `secret-scan` job pins
  `zricethezav/gitleaks:latest` — unpinned, and `zricethezav/gitleaks` is the legacy image name (current
  is `ghcr.io/gitleaks/gitleaks`). The repo's ethos is digest-pinning everything; consider pinning the
  gitleaks image by digest and/or moving to the maintained repo. Non-blocking.

## Ruling on the builder's gate question (recurring `{"key":...}`/token examples in teaching docs)
Two-part answer:
1. **My gate:** I've switched to running the real gitleaks container/binary (done this batch), not the
   diff-grep substitute. Keeping it.
2. **The recurring class:** keep the precise-fingerprint suppression (safest — no broad masking), but
   prefer **prevention over suppression** going forward — author teaching examples with obviously-fake
   placeholder values (like the `<the api_key ...>` this batch switched to, or all-zero/`AAAA…`
   patterns) that don't trip the entropy rule in the first place. Avoid a broad docs-scoped allowlist
   (it would mask genuine secrets accidentally committed in docs). If fingerprint accumulation ever gets
   noisy, an inline `# gitleaks:allow` on the specific line is preferable to any path/rule-level exemption.

## Verdict
**`pass`.** Cleared to merge; merging greens `main`.
