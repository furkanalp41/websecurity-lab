# Review: batch/track-xss-j-chains (PR #25) — PASS

**Auditor:** denetle (independent live verify, Fable 5.1) · **Head:** ff37d70 · **Base:** main (35e8fe6, clean — no shared-doc conflict).
**Lab:** self-xss-csrf-profile-chain (practitioner) — first multi-step chain (self-XSS + CSRF-able GET → account takeover).

## Verdict: PASS — cleared to squash-merge + tag. One NON-BLOCKING observation.

## Live results
- Built + run clean-room under isolated `-p`; flag derived INDEPENDENTLY. Intended chain exploit: exit 0, exfil'd admin session, flag == my HMAC.
- **Technique-necessity HOLDS — both halves required:** the admin cookie is script-readable ONLY on the raw `/profile` (self-XSS necessary), and the bio is default-benign until the token-less `GET /profile/update` plants it using the admin's own cookie (CSRF necessary). No path to the flag skips either. Verified: `/profile` 403 public, `/u/admin` HTML-escaped, and the no-chain negative control (bot views `/profile` with the default benign bio) → 0 beacons.
- **GET-CSRF soundness CONFIRMED:** the attacker `/go?to=` meta-refresh drives a cross-site TOP-LEVEL GET to `/profile/update`, and that carries the admin's SameSite=Lax cookie (proven live — the exploit only succeeds because the cookie rode the cross-site top-level GET). A cross-site POST would NOT carry a Lax cookie (Lax sends only on same-site requests + top-level safe-method cross-site navigations), so exposing the update over GET is the correct vector for an HTTP+Lax lab, not a cop-out. Same-class deviation as batch-h/-i, and sound.
- Posture OK ×4 (app/attacker/collector/bot: non-root, read_only, cap_drop:ALL, no-new-privileges). Anti-bypass: `/profile`, `/profile/update`, `/internal/queue`, `/internal/bot-login(key)` all 403 public. Egress: bot AND attacker origin → 1.1.1.1 unreachable. `LAB_USER_SECRET` dropped from app PID1, no baked flag. gitleaks: no leaks. Diff scope = this lab + shared docs only (no stray files).
- **Trivy:** library gate CLEAN (flask 3.1.1 / gunicorn 23.0.0 / werkzeug 3.1.8 → 0 vulns) and OS gate CLEAN (no fixed CRITICAL), via the session-cached DB with `--skip-db-update` (your local DB *refresh* hangs on this box's network; the cached DB is ~1 day old, so a brand-new last-24h CVE would be caught by CI's fresh-DB gate, which is the final authority — deps are byte-identical to the already-cleared csp-jsonp). CWE-79 + CWE-352 apt.

## OBS-1 (NON-BLOCKING) — the attacker meta-refresh origin is not STRICTLY necessary
Verified live: queuing the app's own `http://app:8080/profile/update?bio=<payload>` directly to `/report` (skipping the attacker `/go` page) ALSO fires — the bot's top-level nav sets the bio and the 302→/profile self-XSS runs. This is materially different from the batch-h/-i BL-1s: the direct path STILL exercises both the self-XSS AND the token-less state-changing GET (the CWE-352 vuln), so the core chain — and the technique-necessity property — remains intact. What it skips is only the cross-site DELIVERY wrapper, and with it the specific SameSite=Lax cross-site demonstration the attacker origin is built to showcase. Not a defect (the flag still requires the full self-XSS+CSRF chain), so PASS stands. If you want the cross-site/Lax lesson to be mandatory rather than illustrative, `/report` could forward only off-app (attacker-origin) URLs — optional polish, your call.

## On the deferred mXSS/DOMPurify labs
Right call deferring them. DOMPurify 3.0.5 resisting the classic corpus (mglyph/noscript/nested-form/annotation-xml/CDATA) matches the current state — 3.0.5 postdates the well-known bypass fixes. Prototype-first (confirm a version-specific bypass in real Chromium, or pin a documented-vulnerable version and verify it live) before building is exactly the discipline; a silently-non-firing sanitizer bypass would be a verification-integrity landmine.

Cleared to squash-merge + tag batch/track-xss-j-chains.
