# Review: batch/track-xss-h-csp (PR #23) — FAIL

**Auditor:** denetle (independent live verify, Fable 5.1) · **Head:** fd2fdf6 · **Base:** main (reviewed branch head as-is; shared-doc conflicts are yours to resolve keep-both).
**Labs:** csp-jsonp-callback-bypass (expert) — CLEAN; csp-base-uri-relative-script-hijack (expert) — BLOCKING FINDING.

## Verdict: FAIL — one blocking soundness defect in csp-base-uri. csp-jsonp is otherwise merge-ready.

## BL-1 (csp-base-uri-relative-script-hijack) — the base-uri technique is UNNECESSARY; a simpler unintended solve defeats the lab's marquee lesson. **BLOCKING.**
The lab's whole identity is "missing base-uri lets you hijack the page's relative `<script src="main.js">`." But the CSP is `script-src 'self'` (no nonce), `?ref=` is a RAW HTML-injection point in `<head>`, and the app serves attacker-uploaded JS SAME-ORIGIN at `/u/<id>/main.js`. So an attacker can inject a same-origin script tag **directly** — no `<base>` at all — and `script-src 'self'` permits it.

VERIFIED LIVE (both paths yield the flag):
- Direct injection: uploaded a beacon bundle → queued `/?ref=<script src="/u/<id>/main.js"></script>` (NO `<base>`) → the bot executed it and exfiltrated `session=…` → that cookie POSTed to /solve returns the flag.
- Intended base-uri exploit (`<base href="/u/<id>/">`): also exit 0, same session, flag == my independent HMAC.
- Negative control (inline `<script>`/`<img onerror>` in ?ref=): 0 beacons — CSP does block inline, as intended.

Why this is blocking (not a bonus rung): the direct injection is STRICTLY SIMPLER than the intended solve and teaches a DIFFERENT thing (`script-src 'self'` + same-origin upload = XSS), so a learner never engages with base-uri — the specific technique the lab is named for and its SOLUTION.md teaches. This is the same class as the WAF/filter-coverage precedent (a marquee technique bypassable by a simpler sibling path → the lesson doesn't hold).

ROOT CAUSE: the classic base-uri bypass REQUIRES a **nonce**-based CSP. A nonce blocks direct `<script src>` injection (the attacker has no valid per-response nonce), so `<base>` becomes the ONLY path — the injected base redirects the *nonced* relative `<script src="main.js">`, and the nonce travels with the element, so the redirected script loads WITH the valid nonce and runs. Your `script-src 'self'` + same-origin-upload redesign makes the base-uri step a red herring.

RECOMMENDED FIX (small): make the legit bundle nonced and the CSP nonce-only for scripts.
- `<script src="main.js" nonce="{{nonce}}"></script>` (fresh unpredictable nonce per response)
- CSP `script-src 'nonce-{{nonce}}'` — DROP `'self'` from script-src (keeping `'self'` re-opens the direct-injection shortcut).
Then: direct `<script src="/u/<id>/main.js">` → BLOCKED (no nonce); `<base href="/u/<id>/">` → the nonced `main.js` resolves to `/u/<id>/main.js` loaded WITH the nonce → runs. base-uri becomes necessary and the classic attack is taught correctly. (With a nonce you could even restore the catalog's foreign-origin `<base>` framing — the nonce travels cross-origin too — but same-origin keeps it self-contained.)

On your soundness ask: you were right that the catalog's foreign-origin `<base>` would be blocked by `script-src 'self'`. But the same-origin redesign didn't just relocate the target — it removed the constraint (the nonce) that makes base-uri necessary at all. The deviation note documents the foreign→same-origin move but misses that base-uri is now optional.

## csp-jsonp-callback-bypass — CLEAN (would PASS on its own)
`?q=` reflected raw, contained by CSP `script-src 'self' http://accounts-trusted:8080` (no unsafe-inline; `base-uri 'none'`; `object-src 'none'`). The allowlisted host's stdlib JSONP endpoint (`/api/jsonp?callback=` verbatim reflection, served application/javascript) is the sole script-exec path — the app has NO upload/same-origin JS gadget, and the 'self' HTML page can't be a JS gadget (doctype prefix throws). Intended `<script src="…/api/jsonp?callback=<JS>//">` exploit exit 0; admin session exfil'd; flag == my HMAC. NEGATIVE CONTROL: inline `<script>`+`<img onerror>` in ?q= → CSP blocks → 0 beacons. Trusted-host is a genuine mock external dep (stdlib), egress-dropped like the bot/collector (verified bot AND accounts-trusted → 1.1.1.1 unreachable), not a gated app. CWE-829 (inclusion of functionality from an untrusted control sphere) is APT — the allowlisted origin's JSONP is untrusted functionality pulled into the app origin. Anti-bypass 403s, LAB_USER_SECRET dropped, no baked flag, Trivy CI-gate CLEAN. 4 services (app + accounts-trusted + bot + collector), posture OK ×4.

## Cross-lab
- Diff scope: 2 lab dirs + shared CHANGELOG/catalog/xss.md (no packages/ change — correct; these gadgets load on page-load, no click). gitleaks: no leaks in either lab.
- Both re-platformed Flask per Hybrid policy.

## To clear the batch
Fix csp-base-uri per BL-1 (nonce-based CSP). csp-jsonp needs no changes. Re-request and I'll re-verify the base-uri lab (direct injection MUST yield 0 beacons; base-uri path MUST still solve).

---
## RE-VERIFICATION (fix landed, head 611e82c) — BL-1 RESOLVED → batch now PASS
Fix: `script-src 'self'` → `script-src 'nonce-<per-response>'` (dropped 'self'); page's own `<script src="main.js" nonce="{{nonce}}">` nonced; per-request `secrets.token_urlsafe(16)` via before_request.
Verified live at 611e82c:
- CSP header is now `script-src 'nonce-…'` and the nonce CHANGES every response (confirmed two distinct nonces on two GETs).
- TEST 1 (technique-necessity control): direct `<script src="/u/<id>/main.js"></script>` injection → **0 beacons** (blocked — no valid nonce, no 'self' fallback).
- TEST 2 (intended): `<base href="/u/<id>/">` → exit 0, admin session exfil'd, flag == my independent HMAC (the nonce rides the ELEMENT so the base-redirected main.js loads with a valid nonce).
- Considered nonce-leak-via-dangling-markup: not a path to the flag (leaking the nonce doesn't execute script, and it's fresh per response, so no leak-then-reuse within one render). base-uri stays necessary.
- csp-jsonp unchanged (git diff fd2fdf6..611e82c touches only the base-uri lab + shared docs). Posture still OK.
**csp-base-uri BL-1 RESOLVED. Both labs clear. Batch PASS.**
