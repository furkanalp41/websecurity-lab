# Review: batch/track-xss-f-framework (PR #20) — PASS

**Auditor:** denetle (independent live verify, Fable 5.1) · **Head:** 8923655 · **Base:** main
**Labs:** jquery-location-hash-selector (practitioner), angularjs-sandbox-escape-172 (expert), vue2-template-compile-injection (expert) — client-side framework template/selector injection.

## Verdict: PASS — all three cleared to merge. No blocking findings.

Each lab was built + run clean-room under an isolated `-p` project, with LAB_USER_SECRET set to a known test value so I derive the flag INDEPENDENTLY (not trusting the exploit's self-check).

## Per-lab live results
1. **jquery-location-hash-selector** — DOM sink `$(decodeURIComponent(location.hash.slice(1)))`, vendored jQuery 3.4.1 (< 3.5) confirmed on disk. Intended exploit exit 0; exfiltrated admin `session`; flag == my HMAC. NEGATIVE CONTROL: `<img src=x>` (construct, no onerror) + a benign `#billing` selector → 0 beacons after the bot visited — proves only real JS execution beacons. Posture OK ×3 (non-root app/botuser/app). /internal/bot-login (even WITH the right key) + /internal/queue → 403 public, no Set-Cookie leak, /solve junk → 403. Egress: bot→1.1.1.1 "Network is unreachable"; collector no default route. LAB_USER_SECRET dropped from app PID1; no baked flag in image. Trivy CI-gate CLEAN.
2. **angularjs-sandbox-escape-172** — `html.escape(name)` reflected into an `ng-app` text region; AngularJS 1.7.2 (sandbox-less) confirmed. Reflection verified live: `?name=<script>` → `&lt;script&gt;`. NEGATIVE CONTROL: escaped `<script>` + escaped `<img onerror>` → 0 beacons. Intended `{{constructor.constructor("…document.cookie…")()}}` CSTI → exploit exit 0, flag == my HMAC. Anti-bypass 403s, egress blocked, collector no route, secret dropped, no baked flag, Trivy CLEAN.
3. **vue2-template-compile-injection** — `Vue.compile(document.getElementById('w').textContent)` on `/admin/dashboard`; Vue 2.7.16 full build. CRUX CONFIRMED: source uses `<div id="w">`+`textContent` (which entity-decodes), so the stored template reaches the compiler; exploit exit 0 — same-origin `fetch('/me')` returns the admin token, beaconed, flag == my HMAC. `/admin/dashboard` + `/me` → 403 public ("forbidden — admin only"). NEGATIVE CONTROL: benign `<span>` template → 0 beacons. Egress blocked, secret dropped, no baked flag, Trivy CLEAN. (I confirm your first-draft `<script type=text/x-template>`+innerHTML would NOT have worked — a raw-text element's content is not entity-decoded, so Vue.compile would receive the escaped/broken template. Your fix to `<div>`+textContent is correct.)

## Your three review asks — VERIFIED
- **Vendored-EOL Trivy stance:** confirmed no `.trivyignore` needed. The vendored jQuery/AngularJS/Vue `.min.js` are served as static files from `src/`, NOT installed packages, so Trivy's library gate (which fingerprints python-pkg METADATA) never sees the framework versions. All 3 app images pass the CI-matched 2-gate (`--ignore-unfixed`; library HIGH,CRITICAL; OS CRITICAL) CLEAN. (Aside: a no-`--ignore-unfixed` scan surfaces ~54 unfixed base-image OS CVEs, but those are exactly what CI's `--ignore-unfixed` + OS-CRITICAL-only gate excludes — not a finding.)
- **CSTI risk:low honest:** yes. Each gadget reaches the `Function` constructor, but it runs only inside the hardened, non-root, read_only, cap_drop:ALL headless Chromium bot on the `internal:true` egress-dropped backend. A stolen cookie/token can reach only the in-lab collector; bot→internet is unreachable. risk:low holds.
- **vue `<div>`+textContent decode is the crux:** confirmed above (and the `<script>`+innerHTML counterfactual would not decode).

## Cross-lab
- Diff scope: only the 3 lab dirs + shared CHANGELOG.md / data/catalog.json / docs/tracks/xss.md. Catalog reconciled placeholder→implemented for ONLY these 3 slugs; tech_stack now exact-matches each meta.json. No collateral drift to other labs.
- gitleaks (filesystem) on all 3 lab dirs: no leaks. BOT_KEY (`xss-bot-shared-key`) is intentionally in the readable compose; the IP firewall (pinned 172.31.240.0/24) is the real gate — verified 403 from public.

## Non-blocking nit (no action required)
- jquery `src/collector.py` docstring still reads "OOB collector sidecar for reflected-xss-search-noescape" — copy-paste leftover from lab 1. Cosmetic; function is correct.

Cleared to squash-merge + tag batch/track-xss-f-framework.
