# Stored XSS via BBCode [img] Attribute Smuggling

> Track: `xss` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**Vault Forum** is a vintage message board. Posts are written in BBCode, and the
board's home-grown renderer turns

```
[img]https://example.test/cat.png[/img]
```

into

```html
<img src="https://example.test/cat.png" />
```

The renderer is careful about _most_ things: every character of the post body is
HTML-escaped, so `<`, `>`, and `&` in ordinary text become inert. But it has one
blind spot — the URL captured between `[img]` and `[/img]` is dropped **raw**
into the `src` attribute, with **no HTML-attribute encoding**. In particular a
double quote in that URL is _not_ turned into `&quot;`.

That single omission is the whole lab. A `"` inside the `[img]` URL closes the
`src` value early, and everything after it becomes **new HTML attributes** on the
`<img>` tag — including event handlers.

You are not the victim. The interesting target is the forum's **admin**,
represented by a headless-Chromium bot that:

- loads the **admin topic board** `GET /admin/topics` every couple of seconds —
  a page you cannot open yourself (it returns `403` without the admin cookie),
  and
- does so **carrying the admin's `session` cookie**, which — through a second
  misconfiguration — is **not** marked `HttpOnly`, so `document.cookie` can read
  it.

Anyone can `POST /topics`. Your topic is stored and rendered on that admin board
the next time the bot loads it. This is **stored** XSS: source (your post) and
sink (the admin's browser) are different requests, by different users.

## Objective

Post a topic whose `[img]` URL smuggles an `onerror` handler out of the `src`
attribute, so that when the admin bot renders the board the handler fires and
ships the admin `session` cookie to the in-lab collector:

```
http://collector:9000/report?c=<the admin cookie>
```

The collector sits on an internal, **egress-dropped** network — a stolen cookie
can reach it but never the real internet. Read what it captured through the
app's proxy:

```
GET /oob/received
```

then submit the recovered session value:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when the value matches the session the admin
bot currently holds.

## Getting Started

1. Confirm the sink. Post `[img]https://x/y.png[/img]` and reason about the HTML
   the renderer emits: your URL lands **inside** `src="..."`. Ordinary body text
   is escaped — so the URL is your _only_ way in.
2. You are inside an attribute value. What single character ends that value and
   lets you write a brand-new attribute on the same tag?
3. `<img src="x" ...>` where `x` is not a real image will fail to load. What
   `<img>` attribute runs JavaScript **on load failure**, with no click needed?
4. A handler that runs in the admin's browser has `document.cookie` in scope.
   How do you get that value out to a host you can read?

**CWE-79 (Improper Neutralization of Input During Web Page Generation),
OWASP A03:2021 – Injection.** The root fix — HTML-**attribute**-encoding the
URL (so `"` becomes `&quot;`) — and the defence-in-depth `HttpOnly` cookie are
discussed in `SOLUTION.md`.
