# Review: batch/track-xss-b-dom (PR #16) — PASS

**Auditor:** denetle (max effort) · **Head:** 45c9940 · **Base:** main (8eef594, clean ancestor)
**Labs:** `dom-xss-hash-document-write` + `dom-xss-innerhtml-jquery-html` (both apprentice DOM-XSS, on the shared xss-verifier).

## Verdict: PASS — both cleared to merge. No blocking findings. Correct new primitives, batch-a OBS-1 applied.

## Verified LIVE (both labs)
Posture PASS all 3 per lab (app=app/10001, collector=app, bot=botuser); bot CapAdd=null (headless Chromium under --no-sandbox with ZERO added caps, read_only, no-new-privileges). Egress-drop holds (bot→1.1.1.1 blocked). /internal/bot-login + /internal/queue 403 from the public side (pinned backend subnet 172.31.240.0/24). Intended exploit exit 0 on both (flag == my independent HMAC), checker green via `$1`. app images 135 MB, trivy library=0/os=0, no baked flag. drift-lint 28, format (with `**/*.min.js` now excluded), typecheck, dockerfile-pin, gitleaks, both meta-schemas — green. Flag+ADMIN_SESSION HMAC-derived per-slug; `--workers 1` (in-process queue). checker.sh arg handling correct.

## Lab 1 — dom-xss-hash-document-write: the NEW same-origin-READ primitive — VERIFIED airtight
Sink is a genuine pure-DOM XSS: `document.write('<h1>Welcome '+decodeURIComponent(location.hash.slice(1))+'</h1>')` — the `#`-fragment is client-side only, no server reflection, so only real browser execution (the Playwright bot) makes it solvable. The prize is a same-origin read: `GET /flag.txt` is cookie-gated. Confirmed the flag is UNREACHABLE without the DOM XSS:
- `GET /flag.txt` no cookie → 403; wrong cookie → 403.
- Submitting `/flag.txt` directly to the bot queue → the bot VISITS it (renders the flag) but the collector stays **count=0** — a bot-visit alone does NOT exfiltrate; you need injected JS doing a same-origin `fetch('/flag.txt')`+beacon.
- Intended exploit (`/#<img src=x onerror="fetch('/flag.txt')…beacon">`) recovers the flag → exit 0.
(No `/solve` here by design — the flag is fetched same-origin and beaconed directly; a valid variation of the primitive.)

## Lab 2 — dom-xss-innerhtml-jquery-html: jQuery .html() sink — VERIFIED
`$('#panel').html(decodeURIComponent(location.hash.slice(1)||'home'))` on load + hashchange. Correctly framed: a bare inline `<script>` via innerHTML won't run, but `<img src=x onerror=…>` fires on parse. Intended exploit (img onerror → document.cookie → collector → /solve) exit 0, flag matches. jQuery served locally (`GET /jquery-3.7.1.min.js` → 200, 87533 bytes) — vendored, works on the egress-dropped net.

## jQuery 3.7.1 deviation — sound, affirmed
Pinning CURRENT jQuery (not the catalog's 3.4.1) is the right call: the taught flaw is the app's own `.html(untrusted)` misuse (version-independent — `.html()` sets innerHTML in every jQuery), and a non-CVE'd jQuery keeps the Trivy gate honest and prevents an unintended solve via a jQuery CVE. Vendored + served locally (no CDN, which the egress-drop would block anyway). trivy library gate confirmed clean on the app image (incl the vendored file). Documented in README/SOLUTION/catalog. Good.

## OBS-1 (from batch-a) — applied
Both SOLUTIONs now carry the explicit `CWE-79, OWASP A03:2021` citation. Depth is apprentice-appropriate (lab1 6 / lab2 5 H2 sections). Good.

## Observations (non-blocking)
- Consistency note: lab 1 has no `/solve` (flag beaconed directly) while lab 2 / batch-a have `/solve`. This is justified by lab 1's same-origin-read primitive (the flag itself is the exfil target, not a cookie to then redeem) — not a defect, just worth being deliberate about as the pattern library grows so learners aren't surprised by the endpoint set varying per lab.
- The OBS-2/OBS-3 items from batch-a (bot-base CI caching; documenting the websec-lab/ vs xssbot/ infra-exempt convention) still apply track-wide; you flagged them as forthcoming. No new instance here.

Clean batch — the DOM-sink verification (no server reflection to lean on) is exactly where the real-browser verifier earns its keep, and both new primitives hold up. Ship it. XSS 3/26 after merge.
