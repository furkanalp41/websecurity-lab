# Review — `ui-phase-1-shell`

- **Reviewer:** denetle (AUDITOR)
- **Reviewed commit:** `b392deaac04a8688f07c03be430502b320b907a9` (`build/ui-phase-1-shell`, 1 commit atop `main` `de83fac`)
- **PR:** https://github.com/furkanalp41/websecurity-lab/pull/2
- **Verdict:** `pass_with_findings` — 2 `must_fix` (objective a11y/WCAG defects, both cheap), 5 `nice_to_have`. No security issues.

Applied the Phase-2 UI checklist (a11y / XSS / CSRF / auth) instead of the exploit-runner items. Built the static export locally (541 pages) and **drove it in a real browser** (Chromium via Playwright): keyboard nav, the live announcer, the ⌘K dialog, and an XSS payload against the flag input were all exercised live, not read off the evidence.

## Verified good

**XSS — clean.** No `dangerouslySetInnerHTML` / `innerHTML` / `eval` anywhere. Every catalog/hint string renders as an auto-escaped React text child. Confirmed in the generated HTML: the only raw `<script>` tags are Next's own chunk loaders; an XSS lab's payload text (`<script>`, `<img onerror>`) appears escaped as `&lt;…` in the served `.html`, and raw only inside the inert RSC `.txt` flight data (served as text/plain, rendered by React as an escaped text node). **Live poke:** typed `<img src=x onerror=…>` into the flag input and submitted → no execution (`window.__pwned` unset), no injected node, status text is a fixed string that never echoes the guess, payload stays as the input's text value.

**CSRF / auth — no surface.** Local-first, no accounts/sessions. Flag submission goes over the bearer-authenticated loopback WS (`labctl-client.ts`), origin-allowlisted server-side. No cookie-based state-changing endpoints.

**Accessibility — largely excellent (verified live):**
- `/map` is `role="application"` with a described keymap; **arrow-key spatial nav works and the `aria-live` announcer fires** — after ArrowUp it announced *"Focused: Column Discovery via ORDER BY on Blog Archive, SQL Injection track, Apprentice, locked."*
- **Text-map** alternative is real `<a>` links per track in `<details>` — full non-visual traversal.
- **⌘K palette** is a native `<dialog>`: opens as a true modal (`:modal=true`), focus lands in the input, filtering works (1 result for "login bypass"), **Escape closes it** (platform focus-trap, verified).
- Global `*:focus-visible` outline; `prefers-reduced-motion` kill-switch; `MatrixRain` honors reduced-motion.

**Static export / hygiene.** 541 lab pages + `/map` prerender (SSG); `build-catalog` now also emits the gitignored `hub/public/labs-index.json`; CI hub-build gained `pnpm run map`. **NTH-6 (arch-000 docstring) is closed** — the build-catalog comment now matches the hard-fail behavior. `/map` console is clean (no hydration errors, no passive-wheel warning).

## `must_fix`

### MF-U1 — Lab pages have no descriptive `<title>` (WCAG 2.4.2) 🟠
All 541 lab pages share the generic root title **"WebSecurity Lab"** (only `/map` sets a descriptive one via `metadata`). Verified live: the sqli lab page's `document.title` is `"WebSecurity Lab"`. Identical titles across 541 distinct pages fail WCAG 2.4.2 (Page Titled) and hurt tab/history/SR orientation and SEO. **Fix:** add `generateMetadata({params})` to `hub/app/lab/[category]/[slug]/page.tsx` returning `{ title: `${lab.title} · WebSecurity Lab` }` (also 404-safe for unknown slugs).

### MF-U2 — ⌘K combobox is missing `aria-activedescendant` (WCAG 4.1.2 / APG) 🟠
The palette input is `role="combobox"` and options carry `aria-selected`, but the input has **no `aria-activedescendant`** and the options have **no `id`** (verified live: `aria-activedescendant` = null). With DOM focus staying in the input, a screen reader is never told which option is active as the user arrows — the core of the combobox pattern. **Fix:** give each option a stable `id` and set `aria-activedescendant={id-of-active}` on the input (and `aria-selected` only on the active option). Small change; there is an accessible fallback (the text-map), which is why this is `must_fix` not blocking-critical.

## `nice_to_have`

- **NTH-U1 (UX, highest-impact):** `/map` opens on the **deepest, all-locked end** of every track. The 20 in-degree-0 track roots (correctly "available") sit at y≈4236–5996 in a 6104px-tall canvas, but `fit()` top-aligns at y=24 and clamps to min-zoom, so **every entry point is culled below the fold** — a first-time user sees a wall of 🔒 with no visible start (verified: 340/340 rendered nodes locked, 0 available on load; roots confirmed available in the map data). For a screen whose tagline is "the map is the game," the camera should land on the available frontier. **Fix:** have `fit()` reveal the roots (e.g., anchor the initial y to the max-y band, or switch elk `direction` to `DOWN` so roots render at top). Note: locked nodes are still clickable/openable, so this is UX, not a functional block.
- **NTH-U2 (a11y/UX):** the ⌘K indicator is an `aria-hidden` `<span>` with no actionable affordance — the palette is discoverable only via the keyboard chord. Add a real `<button aria-keyshortcuts="Meta+K Control+K">` that calls `showModal()` (helps pointer users, SR users, and discoverability).
- **NTH-U3 (UX):** map arrow-key focus doesn't pan the camera, so the focused node (and its ring) can be culled off-screen for sighted keyboard users. Recenter the camera on focus changes (pairs with NTH-U1).
- **NTH-U4 (cosmetic):** the flag input placeholder is `flag{...}` (lowercase) while real flags are `FLAG{…}` (uppercase) and `FLAG_RE` requires uppercase — align the placeholder to avoid confusing learners.
- **NTH-U5 (FYI):** in static/GitHub-Pages mode the browser logs a red `WebSocket … ERR_CONNECTION_REFUSED` (the daemon probe). The app handles it correctly (→ static mode); the error is browser-emitted and can't be swallowed from JS, but worth a one-line note in docs, or gate the WS attempt behind a fast reachability hint. (The 3 font-preload warnings are benign next/font behavior.)

## Disposition

Close MF-U1 and MF-U2 on `build/ui-phase-1-shell`, re-send as `ui-phase-1-shell-r1`. Both are small, objective WCAG fixes and worth locking in on the foundational shell before 541 lab pages and future UI inherit the patterns. NTH-U1 is the highest-impact user-facing item — strongly recommended for r1, but it's a UX call and yours to prioritize.
