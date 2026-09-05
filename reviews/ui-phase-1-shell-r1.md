# Review — `ui-phase-1-shell-r1` (re-review)

- **Reviewer:** denetle (AUDITOR)
- **Reviewed commit:** `14c8011bd91b80a8a8b1bbae50266453e3787e44` (one fix commit atop the merged r0 review `6e55518`)
- **Prior:** `reviews/ui-phase-1-shell.md` — `pass_with_findings` on `b392dea`
- **Verdict:** ✅ **`pass`**

Both `must_fix` and all 5 `nice_to_have` verified — code read straight from git, then the a11y-critical items **re-driven in a real browser** on the fresh static export.

## must_fix — verified closed

| ID | Fix | Verification | Result |
|---|---|---|---|
| **MF-U1** per-page titles | `generateMetadata` on the lab route (404-safe) | Built the export; `sqli` page `<title>` = "Classic Login Bypass on Legacy Guestbook · WebSecurity Lab", `xss` page = "Reflected XSS in Search Results · WebSecurity Lab" — distinct & descriptive (WCAG 2.4.2) | ✅ |
| **MF-U2** combobox `aria-activedescendant` | input sets `aria-activedescendant=cmdk-opt-${active}`; each option has `id=cmdk-opt-N` | Live: opened palette, typed "sql", real ArrowDown → `aria-activedescendant="cmdk-opt-3"` pointing at the single `aria-selected` option ("Second-Order SQLi via Malicious Username"); exactly one option selected (WCAG 4.1.2 / APG) | ✅ |

## nice_to_have — verified

- **NTH-U1** (map opens on frontier): `build-map` elk `direction` UP→DOWN; roots now at **y=12** (top). **Live: 20 available (unlocked) roots render on load** (was 0 available / 340 locked; now 20 available / 320 locked). ✅
- **NTH-U2** (real ⌘K button): `cmdk-button.tsx` dispatches `websec:cmdk`; top-bar renders `<CmdkButton>`; palette listens for the event. **Live: clicking the button (aria-label "Open command palette…") opens the modal.** Old aria-hidden badge removed. ✅
- **NTH-U3** (focus recenters camera): `centerOn()` sets the camera to center the focused node; called from `moveFocus` for both the chosen and origin node — a keyboard-focused node can no longer be culled off-screen. ✅ (code)
- **NTH-U4**: flag placeholder is now `FLAG{...}` (matches `FLAG_RE`). ✅
- **NTH-U5**: `labctl-client.ts` documents the browser-emitted `WebSocket … refused` static-mode message as harmless/uncatchable. ✅

## No regression

XSS surface unchanged — the r1 diff (metadata, option ids, cmdk button, placeholder string, `centerOn`, elk direction, a comment) introduces no `dangerouslySetInnerHTML`/`innerHTML`/sink; all strings still render as escaped text children. Static build green (541 pages, SSG); hub typecheck clean under all 7 strict flags per CI (8/8).

## Disposition

`ui-phase-1-shell` is cleared to merge to `main`. Next batch per the operator's sequencing (a track, or the next UI phase).

_Env note (carried from r0, unchanged): the machine root disk is 100% full — operator's own data (33G Videos, etc.); builds still run via the ext4 root reserve. Both sessions have surfaced it; only the operator should clear personal files._
