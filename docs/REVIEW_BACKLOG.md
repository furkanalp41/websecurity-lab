# Review backlog

Non-blocking findings from `PASS_WITH_FINDINGS` reviews, tracked for a later chore-batch.
Maintained by the AUDITOR (denetle). Items are cleared when a chore-batch fixes them.

| id | batch_tag | item | severity | suggested_fix | added_at |
| --- | --- | --- | --- | --- | --- |
| BL-1 | batch/track-sqli-c | SOLUTION documents <3 distinct payload vectors (json-body-prisma-raw: 2; rails-active-record-hash: 1) | P1 | add ≥3 distinct vectors each (arity/ORDER BY discovery, error/boolean-oracle variant) | 2026-09-06 |
| BL-2 | batch/track-sqli-c | all 6 SOLUTIONs lack an explicit `CVE: <id or N/A>` line; mongo SOLUTION also lacks the OWASP line | P2 | add CVE/N-A line to all 6; add OWASP A03 to mongo SOLUTION | 2026-09-06 |
| BL-3 | batch/track-sqli-c | json-body catalog.json prose inaccurate (`SELECT *` vs `SELECT id,title,status`; "jsonb columns" but cols are text) | P2 | correct catalog description + skill (drift-lint checks tech_stack only, not prose) | 2026-09-06 |
| BL-4 | batch/track-sqli-c | couchdb meta.json inspired_by cites CVE-2022-24706 (unrelated Erlang-dist RCE) | P2 | drop/replace with a genuine NoSQLi analog or "N/A" | 2026-09-06 |
| BL-5 | batch/track-sqli-c | django pins Django 5.1.14 (security-EOL 2025-12-03) | P2 | bump to Django 5.2.x LTS; update meta tech_stack | 2026-09-06 |
| BL-6 | batch/track-sqli-c | rails version drift (README/application.rb/Gemfile say 7.1, ships 7.2.3); stale "rails runner" comment; leftover nokogiri Dockerfile comment; README time 35 vs meta 45; permit(:category) for a nonexistent column | P2 | reconcile to 7.2; remove dead comments; align time; drop/ add category | 2026-09-06 |
| BL-7 | batch/track-sqli-c | graphql cosmetic mangled backticks (SOLUTION.md:38-39); README spells out the breakout; objective claims non-existent resolver rate-limits | P2 | fix markdown; tone down README; align objective | 2026-09-06 |
| BL-8 | batch/track-sqli-c | mongo/django exposed_service.http_path points at a POST-only route (/login, /search) | P2 | point http_path at a GET route (e.g. /health) or confirm the runner doesn't GET it | 2026-09-06 |
