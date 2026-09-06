# AUDITOR review — batch `chore-sqli-c-docs`

- **Branch / head:** `build/chore-sqli-c-docs` @ `e4fe5b7730caa386c152e6227471ae8bb16edaa9`
- **PR:** #7 · **Base:** `main` @ `1b188ca`
- **Responds to:** track-sqli-c `PASS_WITH_FINDINGS` (reviews/track-sqli-c @ 3200a16), BL-1..BL-8
- **Verdict:** **`PASS`** — all 8 backlog items resolved; cleared to merge.

## Scope
main is ancestor. Diff is docs/metadata plus image-affecting changes in **only two labs**: django
(`src/requirements.txt`) and rails (`Dockerfile`, `src/Gemfile`, `reports_controller.rb`,
`config/application.rb`, `db/seed_lab.rb`). The other four labs changed docs/meta only (not in the app
image) → their track-sqli-c gauntlet+trivy results carry forward unchanged.

## Backlog dispositions — all FIXED (verified)
- **BL-1** ✓ json-body SOLUTION now lists 4 payload vectors; rails gained an "Alternative payload
  vectors" section (CASE flip / boolean-direct / two-key / NULLS ordering) — ≥3 each.
- **BL-2** ✓ all 6 SOLUTIONs now carry an explicit `OWASP: A03:2021 · CWE: <89|943> · CVE: N/A` line
  (mongo's OWASP line included).
- **BL-3** ✓ json-body catalog.json description = `SELECT id, title, status …`; "jsonb" gone from catalog.
- **BL-4** ✓ couchdb meta.json inspired_by no longer references CVE-2022-24706 (grep count 0).
- **BL-5** ✓ `Django==5.2.17` (LTS). Rebuilt + re-verified live (see below).
- **BL-6** ✓ rails `config.load_defaults 7.2`; README "Rails 7.2 · ~45 min" (== meta); Gemfile header
  7.2; seed_lab.rb comment now `ruby -r config/environment`; Dockerfile comment corrected;
  `permit(:status)` (nonexistent `:category` dropped). Rebuilt + re-verified live.
- **BL-7** ✓ graphql backticks repaired; README step-3 no longer spells out the payload; the
  non-existent "resolver-level rate limit" claim removed from meta objective + SOLUTION (the Fix section
  still correctly *recommends* rate limiting).
- **BL-8** ✓ mongo & django `exposed_service.http_path` → `/` (both serve a GET landing).

## Live re-verification of the two changed labs (rebuild + gauntlet + trivy)
| lab | build | MB | baked | posture (app+db) | exploit | flag==HMAC | checker | trivy lib/os |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| django-extra-orm (Django 5.2.17) | ✓ | 173 | 0 | GREEN (app,70) | exit 0 | ✓ | PASS | 0 / 0 |
| rails-active-record-hash (permit/load_defaults) | ✓ | 197 | 0 | GREEN (app,70) | exit 0 | ✓ | PASS | 0 / 0 |

The Django LTS bump and the rails changes did not regress anything — both still exploit to the runtime
HMAC flag, pass the posture gate on both containers, carry no baked flag, stay <300 MB, and pass both
trivy gates.

## Other gates (hand-run)
prettier clean · `catalog`+drift-lint green (18 labs, tech_stack unchanged so catalog==meta holds) ·
map · typecheck · 18/18 Dockerfiles digest-pinned · gitleaks 8.21.2 over 35 commits: no leaks.

## Verdict
**`PASS`** — the backlog (BL-1..BL-8) is fully cleared and the two labs with code changes are
re-verified live. No lab exploit/vuln logic changed. Cleared to merge.
