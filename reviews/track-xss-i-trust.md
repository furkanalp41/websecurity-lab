# Review: batch/track-xss-i-trust (PR #24) — FAIL

**Auditor:** denetle (independent live verify, Fable 5.1) · **Head:** 772d9aa · **Base:** main (reviewed branch head as-is; shared-doc conflicts are yours to resolve keep-both).
**Lab:** postmessage-origin-startswith-bypass (practitioner) — postMessage origin-validation.

## Verdict: FAIL — one blocking soundness defect (the prefix-bypass technique is unnecessary). Everything else about the lab is well-built.

## BL-1 — the look-alike / startsWith prefix-bypass is UNNECESSARY: the LEGIT origin is itself a full payload vector. **BLOCKING.**
The lab teaches "the message handler's `e.origin.indexOf('http://widget-host')===0` prefix check is bypassable by a look-alike origin `http://widget-host-evil`." But `widget.py` serves `/frame?msg=<text>` → `parent.postMessage(<text>,'*')` and reflects the attacker-controlled `msg` from EVERY alias — including the legitimate `widget-host`. And `?widget=` lets the attacker point the embedded iframe at any origin. So the attacker can use the LEGIT origin `http://widget-host:8080/frame?msg=<img onerror=…>`, which trivially prefix-matches (it IS the trusted prefix), and never touch the look-alike.

VERIFIED LIVE (three-way test, distinct tags, one queue):
- notwidget (`http://notwidget:8080`, non-prefix-matching): 0 beacons — the origin check DOES filter (good negative control).
- widget-host-evil (look-alike, intended): beacon — exfil'd the admin session (intended bypass works).
- **widget-host (LEGIT): beacon — exfil'd the SAME admin session.** The look-alike is not needed.

Both EVIL and LEGIT solve for the flag. So a learner obtains the flag WITHOUT performing the prefix-bypass — via a strictly simpler path (use the legit host) — defeating the technique the lab is named for. Same class as the WAF/filter-coverage precedent and the csp-base-uri BL-1 in PR #23 (a marquee technique made optional by a simpler sibling path that reuses the same gadget).

ROOT CAUSE: for the prefix-bypass to be the REQUIRED path, the LEGIT `widget-host` must send only SAFE, non-attacker-controlled messages, so the attacker is FORCED to stand up an attacker-controlled LOOK-ALIKE origin to deliver a payload — and only that look-alike passes the flawed prefix check (notwidget doesn't). As built, the legit origin reflects attacker content, so the origin check is moot.

RECOMMENDED FIX: differentiate legit vs. attacker-controlled origins by CONTENT, not just alias name. Since it's one multi-alias service, branch on the Host header in `widget.py`:
- Host == the exact legit `widget-host:8080` → send a FIXED safe message (ignore `msg`).
- Host is a look-alike (`widget-host-evil`, `notwidget`) → reflect `msg` (attacker-controlled).
Then: widget-host (legit) passes the origin check but can't carry a payload; widget-host-evil reflects a payload AND prefix-matches → the intended bypass; notwidget reflects a payload but is rejected by the origin check → the negative control. The prefix-bypass becomes the only path. (Equivalent: two stdlib services — a fixed-message legit widget, and an attacker-controlled reflecting origin aliased widget-host-evil + notwidget.)
After the fix, re-verify: widget-host (legit) MUST yield 0 beacons; widget-host-evil MUST still solve; notwidget MUST stay 0.

## What IS sound (verified — keep these)
- **?widget= escape:** confirmed no attribute breakout — `?widget=http://x"onerror=1` renders `src="http://x&quot;onerror=1"`. The direct-injection shortcut is properly closed. Good.
- **SameSite=Lax topology:** your reasoning is CORRECT. The bot loads ChatCo TOP-LEVEL (Lax session cookie present), the look-alike is the INNER frame, and the sink runs in the authenticated top-level document. The catalog's "attacker frames the target" topology WOULD fail under Lax (ChatCo in a cross-site iframe gets no session cookie). Confirmed the inversion is necessary and right.
- **Negative control (notwidget):** genuinely filtered (0 beacons) — the origin check works for non-prefix origins.
- **CWE-346 (Origin Validation Error) + CWE-79:** apt for the intended lesson.
- Posture OK ×4 (app/widget/bot/collector non-root, read_only, cap_drop:ALL, no-new-privileges). Anti-bypass: /internal/queue + /internal/bot-login(with key) 403 public. Egress: bot AND widget → 1.1.1.1 unreachable. LAB_USER_SECRET dropped from PID1, no baked flag. Trivy CI-gate CLEAN. gitleaks: no leaks. Diff scope = 1 lab + shared docs. Flask (no re-platform needed).

## Cross-cutting note (PR #23 + #24)
Both expert trust-boundary labs share the SAME anti-pattern: the lab ships a gadget (same-origin upload in base-uri; a msg-reflecting frame here) that is reachable by a SIMPLER path than the taught technique, so the technique is optional. The fix pattern is the same each time: constrain the gadget so the taught technique is the ONLY way to reach it. Worth a design check on future trust-boundary labs: "can the flag be obtained WITHOUT the named technique?" If yes, tighten the gadget.

## To clear the batch
Fix BL-1 in `widget.py` (legit host sends fixed content). Re-request and I'll re-verify the three-way test.

---
## RE-VERIFICATION (fix landed, head d9bede1) — BL-1 RESOLVED → PASS
Fix: Host-branch in widget.py — reached as the exact legit Host (`widget-host:8080`, new LEGIT_WIDGET_HOST env) the frame sends a FIXED safe message and ignores `?msg=`; any other host (widget-host-evil, notwidget) reflects `?msg=`. app.py handler (the flawed prefix check) unchanged.
Verified live at d9bede1 (three-way test, distinct tags, one queue):
- widget-host (LEGIT): **0 beacons** — fixed content, carries no payload (yet still passes the origin check).
- notwidget (non-prefix): **0 beacons** — reflects the payload but the origin check rejects it.
- widget-host-evil (look-alike): **1 beacon** — both reflects AND prefix-matches → the intended bypass; admin session exfil'd.
- Intended checker.sh: exit 0, both negative controls enforced, flag == my independent HMAC.
- Attacker can't decouple Host from origin (both come from the iframe src), so reflection now requires a non-legit origin → the prefix-bypass is NECESSARY. Aliases unchanged (widget-host/widget-host-evil/notwidget). Posture OK ×4.
**postmessage BL-1 RESOLVED. Batch PASS.**
