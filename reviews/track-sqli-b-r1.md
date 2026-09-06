# AUDITOR re-review — batch `track-sqli-b-r1`

- **Branch / head:** `build/track-sqli-b` @ `28036b77b5a540cebc8c898691b9e394438ade9f`
- **Previous head:** `bbd1efe` (my `pass_with_findings`, `reviews/track-sqli-b.md` @ `9e473c7`)
- **PR:** #4 · **Base:** `main`
- **Verdict:** **`pass`** — cleared to merge.

## Scope proof (why no full re-run was needed)
`bbd1efe` is an ancestor of `28036b7` (added commits, no history rewrite). The entire r1 diff is
**8 files, docs + metadata only**:

```
labs/sqli/sqli-header-user-agent-analytics/meta.json    | 2 +-   (max_lifetime)
labs/sqli/sqli-limit-offset-postgres/meta.json          | 2 +-   (max_lifetime)
labs/sqli/sqli-time-blind-mysql-sleep/SOLUTION.md       | 4 +-   (P1)
labs/sqli/sqli-time-blind-mysql-sleep/hints/3.md        | 2 +-   (P1)
labs/sqli/sqli-time-blind-mysql-sleep/meta.json         | 2 +-   (max_lifetime)
labs/sqli/sqli-waf-bypass-whitespace-tabs/README.md     | 12 +-  (minor)
labs/sqli/sqli-waf-bypass-whitespace-tabs/SOLUTION.md   | 9 +    (minor)
labs/sqli/sqli-waf-bypass-whitespace-tabs/meta.json     | 2 +-   (max_lifetime)
```

**Zero changes** to any `src/`, `entrypoint.sh`, `Dockerfile`, `docker-compose.yml`, `tests/`, or
`requirements.txt`. `meta.json` and `.md` do not enter the app image. Therefore every dynamic result
from the `bbd1efe` gauntlet — clean build (159–179 MB), no baked flag, posture gate green on both
containers, exploit lands the runtime HMAC flag <60 s, trivy two-call gate green ×6 — **carries forward
unchanged**. Re-running would be theatre; the code paths are byte-identical to what I already hand-verified.

## Findings dispositions

- **P1 (required) — FIXED.** `SOLUTION.md:140-141` now reads "capped at **4 workers on purpose** … the
  same number as the server's `gunicorn --workers 4`"; `hints/3.md:25` now reads "server workers
  (4 here)". Matches the shipped `entrypoint.sh --workers 4` and `exploit.py POOL_WORKERS=4`. A grep of
  the lab's docs confirms no stale "2 workers" reference remains. The lab now teaches the correct
  pool==workers relationship.
- **P2 (max_lifetime ≤ estimated) — FIXED.** `max_lifetime_minutes` raised to **60** on header (35/60),
  limit-offset (30/60), time-blind (35/60), waf-whitespace (30/60). error-based (25/30) and
  waf-versioned (28/30) left as I ruled them fine. All 6 now have lifetime > estimate.
- **P2 (catalog.json tech-stack drift) — DEFERRED, correctly.** Not in this r1: reconciling
  `data/catalog.json` enacts the Flask-uniform-vs-preserve-diversity product decision I escalated to the
  operator. Per my r0 ruling this does not gate the batch. To be handled as a follow-up once the operator
  rules (reconcile for implemented labs, or keep the diverse spec + schedule rebuilds), ideally with a
  `build-catalog` lint so it cannot silently drift again.
- **Minors — FIXED.** waf-whitespace `README.md` no longer names the specific bypass bytes
  (`/**/`, `%0a`, parens) — genericized to "the many other separators a SQL parser happily accepts",
  with "(the hints spell out the specific bytes)", restoring progressive disclosure (grep-confirmed).
  `SOLUTION.md` gained an explicit in-app-filter-vs-WAF-container deviation note, at parity with the
  versioned-comments lab.

## Re-run gates (metadata changed)
`prettier --check .` clean · `pnpm run catalog` green (12 labs schema-valid — the 4 `meta.json` edits
validate) · `pnpm run map` green (541 nodes / 521 edges).

## Verdict
**`pass`.** All required and should-fix findings resolved; the sole deferred item is an operator product
decision that does not gate this batch. Clear to merge to `main`.
