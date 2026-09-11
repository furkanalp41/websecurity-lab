# Solution — postMessage XSS via startsWith Origin Check

## Vulnerability class

**CWE-79 · CWE-346 (Origin Validation Error) · OWASP A03:2021 – Injection** — a
`window.postMessage` handler trusts the sender with a **prefix** origin check
(`startsWith` / `indexOf(...)===0`) and writes `event.data` with `innerHTML`. A
page on a look-alike origin that merely _begins with_ the trusted string passes the
check and injects HTML that runs in the victim's authenticated document.

## The sink

ChatCo's host page:

```js
window.addEventListener('message', function (e) {
  if (e.origin.startsWith('http://widget-host')) {
    // the flaw
    document.getElementById('slot').innerHTML = e.data; // the sink
  }
});
```

Two problems compound:

1. **The origin check is a prefix test, not an equality test.** `startsWith('http://widget-host')`
   accepts `http://widget-host` **and** `http://widget-host-evil:8080`,
   `http://widget-hosting.example`, etc. There is no `/` or end-of-string delimiter,
   so the trusted string is a _prefix_ of infinitely many attacker origins. (The
   same bug appears as `indexOf(origin) === 0`, or a regex `^https://trusted` with
   no `$`, or `origin.includes('trusted')`.)
2. **`event.data` is written with `innerHTML`.** Even if you trusted the sender,
   rendering message data as HTML is an XSS sink. Here it lets an `<img onerror>`
   run.

## Reaching it — and why the top-level page matters

The host page picks its iframe from `?widget=` (escaped into the `src`, so there is
no attribute-breakout shortcut — the origin check really is the only door). So we
point `?widget=` at a frame on the **look-alike origin**:

```
/?widget=http://widget-host-evil:8080/frame?msg=<img src=x onerror=…>
```

The lab resolves `widget-host-evil` (a second alias on the same widget service) on
its network, standing in for a registered look-alike host. That frame does:

```js
parent.postMessage(<msg>, '*');
```

so the payload travels **up** to ChatCo's top-level handler. `e.origin` is
`http://widget-host-evil:8080`, which prefix-matches, so the handler runs
`slot.innerHTML = '<img src=x onerror=…>'` **in ChatCo's own top-level document** —
which the admin bot loaded directly and is therefore authenticated. `document.cookie`
is the admin `session`, and the beacon carries it out.

> **Why not "attacker page frames the target"?** The obvious topology — the bot
> visits an attacker page that embeds ChatCo in an iframe and messages _it_ — does
> **not** work here. ChatCo's `session` cookie is `SameSite=Lax`, which a browser
> does **not** send to a **cross-site iframe**. So a framed ChatCo would be
> unauthenticated and `document.cookie` empty. Landing the sink in the **top-level**
> ChatCo page (bot navigates to it directly; the look-alike is the _inner_ frame)
> keeps the cookie in scope. The lab's delivery reflects that.

## Why the look-alike is necessary (not the legit widget)

`?widget=` accepts any origin — so why not just point it at the **legit**
`http://widget-host:8080/frame?msg=<img …>`, which trivially prefix-matches? Because
the **legit widget origin sends only a fixed, safe message and ignores `?msg=`**. A
message from `widget-host` passes the origin check but carries no attacker payload.
So a working attack needs a frame that does **both**: reflects an attacker-controlled
`msg` **and** passes the origin check. Only the look-alike does both:

| Frame origin                    | Reflects your `msg`? | Passes `startsWith('http://widget-host')`? | Result        |
| ------------------------------- | -------------------- | ------------------------------------------ | ------------- |
| `widget-host` (legit)           | no — fixed safe text | yes                                        | **0 beacons** |
| `notwidget`                     | yes                  | no                                         | **0 beacons** |
| `widget-host-evil` (look-alike) | yes                  | yes                                        | **executes**  |

That is precisely what makes the prefix flaw load-bearing — take it away (fix the
origin check to exact-match) and there is no frame that both carries a payload and
is accepted.

## Verification integrity — the negative controls

`tests/exploit.py` runs **both** controls before the exploit and fails if either
beacons:

- `http://notwidget:8080/frame` — a non-prefix-matching origin. It reflects the
  payload but the origin check **rejects** it → 0 beacons (the check genuinely
  filters; the bypass is specifically the prefix flaw, not an absent check).
- `http://widget-host:8080/frame` — the **legit** origin. It passes the origin check
  but sends fixed safe content → 0 beacons (the legit origin cannot be weaponised, so
  the look-alike is required).

Only then does it run `widget-host-evil` (reflects + prefix-matches) and succeed.

## End-to-end

```
# 1. (control) a non-matching origin is rejected — 0 beacons.
POST /report {"url":"/?widget=http://notwidget:8080/frame?msg=…"}

# 2. Queue the look-alike-origin frame that messages the payload:
POST /report {"url":"/?widget=http://widget-host-evil:8080/frame?msg=<img src=x onerror=…>"}

# 3. Bot loads ChatCo top-level; the look-alike frame messages up; the flawed
#    startsWith passes; innerHTML runs the payload in the authenticated page.

# 4. Read the collector, submit the session:
GET  /oob/received            # /report?c=session%3D<32 hex>
POST /solve   {"c":"<32 hex>"}      →  FLAG{…}
```

## Why the containment holds

- App + widget + collector + bot live on a `backend` network with `internal: true`
  — **no route off the host**. The stolen cookie reaches the in-lab collector but
  never the internet, so the lab ships a real cookie-theft primitive at `risk: low`.
- `/internal/bot-login` + `/internal/queue` are firewalled to the backend subnet
  (login also gated by `BOT_KEY`), so a public visitor cannot mint the admin cookie
  or read the queue and skip the XSS.
- The `?widget=` value is HTML-escaped into the iframe `src`, so there is no
  attribute-breakout shortcut around the postMessage lesson.
- Single gunicorn worker: the queue and admin session live in-process.

## The fix

1. **Compare `e.origin` for EXACT equality against an allowlist — the real fix.**
   ```js
   const ALLOWED = 'http://widget-host:8080';
   if (e.origin === ALLOWED) {
     /* … */
   }
   ```
   Never `startsWith` / `indexOf` / `includes` / an unanchored regex on an origin —
   the origin is a full `scheme://host:port` string and only whole-string equality
   is safe.
2. **Do not render message data as HTML.** Treat `event.data` as data: use
   `textContent`, or accept only a strict, typed schema (e.g. `{type, value}` with
   `value` inserted as text). `innerHTML` on any untrusted string is XSS regardless
   of the origin check.
3. **Defence in depth.** A `frame-ancestors` / `Content-Security-Policy` and a
   documented message protocol (verify `e.source` is the expected frame, echo a
   nonce) further harden the channel. `HttpOnly` on the session cookie would block
   the `document.cookie` read specifically (though not other same-origin damage the
   XSS could do).

## Deviation from the catalog stack

The catalogued scenario ships a **wildcard-DNS resolver** plus a second **nginx**
vhost so an attacker can "register" a look-alike hostname like
`widget.chatco.internal.evil.lab`. This lab reproduces the exact condition with
**docker network aliases** — one stdlib widget service answers to both
`widget-host` (legit) and `widget-host-evil` (look-alike, prefix-matching) — and a
**Flask** host page with a `?widget=` embed point. It also lands the sink in the
**top-level** authenticated page rather than a framed target, because a
`SameSite=Lax` cookie is absent in a cross-site iframe (see above). The taught bug —
a prefix origin check on a `postMessage` handler with an `innerHTML` sink — is
identical; DNS and nginx are incidental plumbing. The Playwright verifier stands in
for Puppeteer.
