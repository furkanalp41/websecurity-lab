# Review: batch/track-xss-a-reflected (PR #15) — PASS

**Auditor:** denetle (max effort) · **Head:** 6b34f92 · **Base:** main (498fecb, clean ancestor)
**Deliverables:** (1) `packages/xss-verifier` shared Playwright victim-bot (shapes all 26 XSS labs); (2) `reflected-xss-search-noescape` (apprentice) — first XSS lab + first verifier consumer.

## Verdict: PASS — cleared to merge. Strong pattern-setter for the XSS track. No blocking findings; a few forward-looking observations.

## Verifier package (packages/xss-verifier) — the important one, reviewed as shared infra
- **Verification integrity is REAL and un-fakeable.** `bot.py` drives a genuine headless Chromium (Playwright `page.goto(wait_until="load")` + settle delay for async payloads) carrying the victim's cookie; a payload's `document.cookie` exfil only fires if JS actually executes. PROVEN live two ways: (a) the intended `<script>` exploit exfiltrates the admin session (exit 0); (b) a NON-JS payload (`<b>…</b>`, collector reset first) produced **0 beacons** — you cannot solve without real execution. `/solve` is gated on the actual 32-hex cookie value, so there is no reflection-grep false-positive path.
- Env-driven generic image (XSSBOT_ORIGIN/LOGIN_URL/QUEUE_URL/FIXED_URL/COOKIES/…), no per-lab bot code — one image serves all 26. Runtime session establishment via the login URL (secret never baked). Digest-pinned Playwright base, non-root botuser.
- **"≥1 lab imports it" contract satisfied:** the lab's compose builds the bot from `context: ../../../packages/xss-verifier` (pip-installs the package).

## Your 5 flagged review areas — verdicts
1. Verifier design + imports contract → sound (above).
2. **xssbot/ naming + tier:** acceptable. The CI size-cap/Trivy steps grep `^websec-lab/ | head -1`, so they gate the app image (135 MB, collector shares it) and the bot (`xssbot/…`, 2.48 GB browser infra) is exempt — exactly like a pulled DB engine. XSS labs stay standard-tier (PR-blocking CI on the app). Right call.
3. **Anti-bypass — VERIFIED can't get the cookie without the XSS:** `/internal/bot-login` (even with the correct BOT_KEY) and `/internal/queue` both 403 from the public side; the IP firewall (`_from_backend()` vs the PINNED backend subnet 172.31.240.0/24) is the real gate; no Set-Cookie leak, no secret/flag on any public endpoint, no SSRF path to `/internal/*`. The pinned `ipam.subnet` makes the firewall deterministic.
4. **--no-sandbox risk:low — HONEST.** `docker inspect` bot → `CapDrop=[ALL]`, `CapAdd=null`, non-root botuser, read_only, no-new-privileges. Chromium runs with `--no-sandbox` under ZERO added caps; it only visits lab-controlled origins on an egress-dropped net (bot→1.1.1.1 blocked, collector no default route). Disabling the in-browser sandbox doesn't widen the surface because the CONTAINER sandbox contains the browser and there's no egress. Good.
5. **CI scaling (26 labs × ~2.3 GB bot):** the Playwright base + package layers are identical across all XSS labs, so Docker layer caching means the 2.3 GB is built/pulled once and reused; incremental per-lab is the tiny package layer. Manageable, but watch nightly/PR wall-clock + runner cache hit-rate as the 26 labs land — see OBS-2.

## Lab gauntlet — GREEN
Posture PASS all 3 (app=app/10001, collector=app, bot=botuser; read_only, cap_drop:ALL, no-new-privileges, pids/mem; app loopback-only, collector+bot no host port). App runs `--workers 1` (the in-process report queue + ADMIN_SESSION need single worker). Intended exploit exit 0 in 1.6s (exfil'd session + flag == my independent HMAC), checker green via `$1`. Flag hygiene: FLAG + ADMIN_SESSION both HMAC-derived per-container; `unset LAB_USER_SECRET` VERIFIED on the app process (`/proc/1/environ` count 0 — the `docker exec env` view is just Config.Env, not the process/attacker-reachable env); no baked flag/session in the image. App 135.3 MB. trivy library=0/os=0 (app image; xssbot/ exempt by design). gitleaks clean, drift-lint 26, format, typecheck, dockerfile-pin, meta-schema green. checker.sh uses the correct `${1:-${TARGET:-…}}` arg handling (MSSQL BL-2 lesson applied). Scope clean.

## Non-blocking observations
- OBS-1 (docs depth, forward-looking): SOLUTION is complete for an apprentice lab (sink / delivery / payload / end-to-end / containment / two independent fixes) but lighter than the elite SQLi SOLUTIONs (6 H2 sections; no explicit `> OWASP: A03 · CWE: CWE-79` citation line like the SQLi labs carry). Fine here; for the harder XSS labs scale the depth + add the OWASP/CWE citation for cross-track consistency.
- OBS-2 (CI cost to watch): 26 XSS labs each build/run the ~2.3 GB bot. Layer caching mitigates, but confirm the PR matrix / heavy-nightly runners actually reuse the base layer (GH Actions matrix jobs don't share a local docker cache by default) — otherwise 26× a 2.3 GB pull. If it bites, consider prebuilding/pushing one shared xssbot base or a buildx cache.
- OBS-3 (infra-exempt mechanism): the size/Trivy exemption rides on the `^websec-lab/` vs `xssbot/` naming convention in the CI grep — works, but it's implicit. A short comment or a manifest of "infra image prefixes" would make the exemption auditable as more infra images appear.

Genuinely strong foundation — the verifier's real-execution guarantee is exactly right, and the anti-bypass firewall holds. Ship it; the 26-lab track has a solid base.
