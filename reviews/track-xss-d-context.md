# Review: batch/track-xss-d-context (PR #18) — PASS

**Auditor:** denetle (max effort) · **Head:** 192a27d · **Base:** main (92895ae, clean ancestor)
**Labs:** reflected-xss-js-string-break-out (apprentice), iframe-srcdoc-attribute-injection (practitioner), blind-xss-admin-user-agent-log (practitioner) — the three XSS delivery models with context/filter twists.

## Verdict: PASS — all three cleared to merge. No blocking findings.

## On the workflow/agent authoring provenance
You flagged these were parallel-authored by a workflow (3 author agents + 3 adversarial reviewers). I did NOT lean on that or your clean-room claims — I built and live-verified all three independently (posture, anti-bypass, the two same-origin reads, the Bleach behavior probe, real-browser execution, egress, gates). They are clean and cross-consistent (same risk/tier/CWE, same anti-bypass pattern, per-slug HMAC, no copy-paste divergence). So the multi-agent authoring + your read + my independent adversarial pass produced solid labs — a useful data point for scaling.

## Your two key asks — VERIFIED LIVE
### Two cookie/token-gated same-origin READS (labs 1 & 3) — neither secret reachable publicly
- Lab 1: `GET /api/whoami` from the public side returns `{"user":"guest"}` (NO token); the token is disclosed ONLY to a request carrying the admin cookie. The XSS reads it via a credentialed same-origin fetch. Exploit exit 0 (token + flag == my HMAC).
- Lab 3: `GET /admin/apikey` public → 403 (and `/admin/logs` → 403). The key is disclosed only to the admin cookie; the blind payload chains `fetch('/admin/apikey')` in the bot. Exploit exit 0.
- (Nice pedagogy in both: HttpOnly would NOT help — the secret is read via a credentialed fetch, not document.cookie — so output encoding is the real fix. Documented.)

### Bleach srcdoc misconfig (lab 2) — genuine + NO simpler unintended solve
Probed `bleach.clean` live via the /posts echo:
- `<iframe srcdoc="<script>…">` → KEPT, value HTML-escaped (`srcdoc="&lt;script>…"`).
- bare `<script>` → stripped to text; `<img src=x onerror=…>` → stripped to ''; `<a href="javascript:…">` → href removed; `<iframe src="javascript:…">` → src removed.
So the iframe srcdoc is the ONLY XSS path. Exploit exit 0 — the browser decodes the escaped srcdoc and runs the `<script>` in `about:srcdoc` (inherited origin), reading the PARENT's non-HttpOnly `document.cookie`. Bleach 6.2.0, trivy library gate clean.

## Per-lab twist verification
- **Lab 1 (JS-string context):** the "sanitiser" strips only `<`/`>`; confirmed live `/?promo=A<b>C` → `var promo='AbC'`. That's the wrong encoder for a JS string — the exploit breaks out with `'` and (correctly) avoids angle brackets, using `function(){}` not `=>` (an arrow's `>` would be stripped). Works.
- **Lab 3 (blind):** confirmed the UA is stored but NEVER reflected to the sender (a `<blind-probe-marker>` UA does not appear on the public page). The `_SKIP_LOG` exclusion of /health,/admin,/internal,/oob,/solve keeps the bot's own polling from evicting the payload from the maxlen-50 ring buffer — the payload persists and fires when the bot renders /admin/logs.

## All three — GREEN
Posture PASS x3 per lab (app=app/10001, collector=app, bot=botuser; read_only, cap_drop:ALL, no-new-privileges, **bot CapAdd=null** under --no-sandbox). Anti-bypass: /internal/* 403 from public, admin routes 403 without the cookie, pinned backend subnet. Egress-drop (bot→1.1.1.1 blocked). app images 135-136 MB, no baked flag, trivy library=0/os=0 (incl Bleach 6.2), gitleaks clean, drift-lint 32, format/typecheck/dockerfile-pin/meta-schema green. SOLUTIONs carry CWE-79/OWASP-A03 (7/7/10 H2 sections). Re-platform deviations (Express/EJS, FastAPI+Redis → Flask) documented in README/SOLUTION. Scope clean (3 lab dirs + CHANGELOG/catalog/docs). Flags per-slug HMAC (all matched my independent derivation).

## Observations
None blocking. Three genuinely distinct, well-implemented context/filter twists; the same-origin-read variant (secret behind an API, HttpOnly-immune) is a strong addition to the cookie-theft pattern. (Track-wide OBS-2/OBS-3 from batch-a — bot-base CI caching + documenting the websec-lab/ vs xssbot/ convention — still pending your infra touch; no new instance.)

XSS 7/26 after merge. Solid batch.
