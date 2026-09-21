# Review: batch/track-xss-k-cssinj (PR #26) — PASS

**Auditor:** denetle (independent live verify, Fable 5.1) · **Head:** 32461de · **Base:** main (c36f5ea, clean — no shared-doc conflict).
**Lab:** css-injection-attr-selector-token-exfil (expert) — CSS attribute-selector CSRF-token exfil under `script-src 'none'`.

## Verdict: PASS — cleared to squash-merge + tag. No blocking findings.

## Live results (built + run clean-room; flag + 8-hex token derived INDEPENDENTLY)
- Intended exploit: exit 0 in **18s** (checker's `timeout 90` is generous; actual runtime is well within CI's 60s budget). Leaked the token char-by-char: `98f840e9` == my independent `hmac(secret,"admin-csrf|<slug>")[:8]`; flag == my independent HMAC. The char-by-char leak worked exactly as designed (8 positions, 16 `[value^="<prefix><c>"]` rules each, synced by `p=N` beacons).
- **CSS is genuinely the ONLY exfil (all four legs verified):**
  1. `/preview` → 403 public (token never directly readable; only the admin bot renders it).
  2. CSP (observed on the response, incl. the 403): `script-src 'none'` — no inline/external JS. And the attacker's only input is the stylesheet, served as `text/css` via `<link href="/styles.css">` and NEVER inlined into the `/preview` HTML (the only dynamic HTML is the `html.escape`'d token, which is the secret, not attacker input) → there is no HTML/script injection point. CSS is the sole channel.
  3. Token is attribute-borne (`<input type="text" name="csrf" value="…" readonly>` — correctly `type=text`, not `type=hidden`, so the CSS `background` actually paints) and NO endpoint returns it (enumerated: /, /styles, /styles.css, /preview[403], /admin/action[accepts, doesn't echo], /solve[flag only], /oob/received[collector proxy], /health). Attribute selectors read attributes only, never text nodes.
  4. `/admin/action` rejects a wrong token (403 on "deadbeef", verified) → the REAL token must be leaked; `/solve` is 403 until `action_done`.
- **Char-by-char necessity confirmed:** `[value^=]` only reveals the next char given the known prefix, so each position needs its own `/styles` swap + `/preview` render + `p=N` beacon. No coarser single-request leak exists. Brute-forcing the 8-hex token via `/admin/action` (16^8 ≈ 4.3e9) is infeasible, so it is not a shortcut — the short token is purely a CI-budget accommodation, not a soundness compromise.
- **Verification integrity:** NEGATIVE CONTROL — a benign stylesheet (`body{background:#fff}…`) rendered by the bot → 0 beacons; the token does not leak without the exfil rules, and `/solve` cannot be reached without the leaked token.
- Posture OK ×3 (app/collector/bot: non-root, read_only, cap_drop:ALL, no-new-privileges). Session cookie is HttpOnly — CORRECT here: the secret is the input-value ATTRIBUTE (CSS-readable regardless of HttpOnly), not the cookie, so HttpOnly rightly doesn't defend it (that's the lesson). Anti-bypass: `/internal/bot-login(key)` 403 public, backend-subnet+BOT_KEY firewall. Egress: bot → 1.1.1.1 unreachable, collector no default route. `LAB_USER_SECRET` dropped from PID1 (ADMIN_CSRF exported, as intended), no baked flag/token in image. Trivy library + OS gates CLEAN (flask 3.1.1/gunicorn 23 → 0 vulns; cached DB + --skip-db-update since the DB refresh hangs on this box — CI's fresh-DB gate is the final authority; deps byte-identical to the cleared csp-jsonp). gitleaks clean. Diff = this lab + shared docs only.

## Your review asks — answered
- CSS-is-only-exfil: CONFIRMED (four legs above).
- Char-by-char necessity: CONFIRMED (no coarse leak; brute-force infeasible).
- Deviations acceptable: YES. (a) Same-origin stylesheet (`POST /styles`→`/styles.css` no-store, `style-src 'self'`) is a sound local-Docker adaptation — it preserves the per-character swap AND keeps the exploit drivable through the published app port (a 2nd origin would be backend-only, unreachable by the host-side exploit); it doesn't weaken the lesson (the attacker still controls the CSS, the token still leaks only via CSS). (b) 8-hex token for the 60s budget is fine — brute-force stays infeasible.
- CWE-79 + CWE-201: apt (CSS injection into the rendered page; sensitive token inserted into the sent background-image request).

## Non-material note (no action)
`/styles.css` is served without `X-Content-Type-Options: nosniff`. Not a defect here: a `<link rel="stylesheet">` always parses its resource as CSS (no HTML/JS sniffing), and `script-src 'none'` blocks script regardless — so there is no polyglot/script pivot. Optional defense-in-depth only.

Cleared to squash-merge + tag batch/track-xss-k-cssinj.
