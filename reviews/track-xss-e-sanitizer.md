# Review: batch/track-xss-e-sanitizer (PR #19) — PASS

**Auditor:** denetle (independent live verify) · **Head:** bad63fa · **Base:** main (b980e80, clean ancestor)
**Labs:** reflected-xss-script-tag-filtered-ladder, stored-xss-svg-avatar-upload, bbcode-parser-img-attribute-smuggling (all practitioner) — filter / sanitiser / parser bypass.

## Verdict: PASS — all three cleared to merge. No blocking findings.

## On the caught bug + agent authoring
You disclosed the SVG lab's Flask `<uuid>` converter (matches dashed-UUID) vs uuid4().hex store keys → /avatars/<id>.svg would 404, caught by your read-then-verify (the static agent-reviewers missed it), fixed to the string converter. VERIFIED FIXED: the code uses the default string converter on both /avatars/<avatar_id>.svg and /u/<avatar_id>, and the exploit runs end-to-end — upload → /u/<uuid> → the bot's `<object data="/avatars/<uuid>.svg">` LOADS the SVG (200, not 404) → its `<script>` runs in-origin → fetch('/admin/token') → exfil. Had the 404 survived, the <object> would load nothing and there'd be no exfil; the exploit's success is the end-to-end proof. Good data point: the human-read + independent-verify backstop is what catches what the static agent-reviewers don't. I verified all three independently (not leaning on the clean-room claims).

## Your three key asks — VERIFIED LIVE
1. **SVG-as-document (lab 2):** `<object type="image/svg+xml">` runs the SVG `<script>` in the app's OWN origin, so a same-origin `fetch('/admin/token')` sends the admin cookie — exploit exit 0 (token + flag == my HMAC). `/admin/token` → 403 to the public. Upload validation: non-`image/svg+xml` mimetype → 415; the scripted SVG (svg mimetype + `<svg` prefix, no body sanitisation) is accepted. `avatar_id` interpolated into /u is route-matched-and-in-store (uuid4 hex) — not attacker-injectable, so no reflected XSS there.
2. **Filter ladder (lab 1):** confirmed the single-pass substring blocklist strips its 4 tokens — live: `<img ... onerror=y>` → `<img ... y>` (onerror= gone), `<script>` stripped — while `<svg onload=y>` sails through (not on the list). Intended `<svg onload>` payload auto-fires (no click) → cookie theft, exit 0. Incompleteness is the lesson; nesting reconstruction (`<scr<script>ipt>`) and `onload=`/whitespace-`onerror` are additional intended rungs, not unintended trivial solves.
3. **bbcode (lab 3):** only the `[img]` URL (`m.group(1)`) goes RAW into `src="..."`; everything else is `html.escape`d (surrounding post text AND the title on the admin board — `html.escape(t["title"])`, confirmed in `admin_topics`). So the `[img]` URL attribute breakout (`x" onerror="…`) is the SOLE vector — exploit exit 0. `/admin/topics` → 403 public.

## All three — GREEN
Posture PASS x3 per lab (app=app/10001, collector=app, bot=botuser; read_only, cap_drop:ALL, no-new-privileges, **bot CapAdd=null** under --no-sandbox). Anti-bypass: /internal/* + admin routes 403 from the public side (pinned backend subnet). Egress-drop (bot→1.1.1.1 blocked). app images 135 MB, no baked flag, trivy library=0/os=0, gitleaks clean, drift-lint 35, format/typecheck/dockerfile-pin/meta-schema green. SOLUTIONs carry CWE-79/OWASP-A03 (8/9/7 H2). Flags per-slug HMAC (all matched my independent derivation). Scope clean (3 lab dirs + CHANGELOG/catalog/docs). Cross-lab consistent (risk:low/standard/CWE-79, same anti-bypass pattern, no divergence).

## Observations
None blocking. Three genuinely distinct sanitiser/parser-bypass twists; the SVG-`<object>`-in-origin one is a strong, subtle addition (and the `<img>`-would-be-safe contrast is correctly built + documented). (Track-wide OBS-2/OBS-3 from batch-a — bot-base CI caching + documenting the websec-lab/ vs xssbot/ convention — still pending your promised track-xss-infra batch; no new instance.)

XSS 10/26 after merge. Solid batch.
