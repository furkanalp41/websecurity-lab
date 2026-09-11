# HTML5 formaction Attribute Injection

> Track: `xss` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**FormFlow** is a small content-management tool. Contributors draft "content
blocks" in rich HTML — including a styled call-to-action **`<button>`** — and an
editor reviews each draft before it is published.

Drafts are sanitised with a real allow-list sanitiser (nh3, the Rust _ammonia_
binding). It does its job on the obvious things: `<script>` is removed,
`onerror=`/`onclick=` handlers are stripped, `href="javascript:…"` is neutralised.
A benign scripted payload simply does not survive. But the allow-list was written
to permit a styled CTA button — and it lets that button keep two HTML5 attributes:

```
formaction   formmethod
```

The editor reviews a draft here:

```
GET /admin/review        (editor session required — 403 otherwise)
```

That page renders the draft **inside the editor's approve form** — a
`<form method="post">` that has **no `action`** (so it submits to the current URL
by default) and carries the editor's anti-CSRF token in a hidden field:

```html
<form method="post">
  <input type="hidden" name="csrf" value="…the editor's CSRF token…" />
  <input type="hidden" name="block_id" value="b1" />
  <div class="draft">…your sanitised draft, CTA button and all…</div>
  <button type="submit" name="decision" value="approve">Approve draft</button>
</form>
```

The editor is a headless-Chromium bot that, every couple of seconds, loads
`/admin/review` with its session and **clicks the CTA button in the draft**
(`.draft button`) to preview where it goes — exactly what a human reviewer does.

## Objective

`formaction` on a `<button>` **overrides the form's submit target** for that
button. So a CTA button you inject can redirect the editor's approve form to your
own listener — and the form body it carries includes the **CSRF token**. Point it
at the in-lab collector:

```
http://collector:9000/report      (POST)
```

The collector sits on an internal, **egress-dropped** network — the token can
reach it but never the real internet. Read what it captured through the app's
proxy:

```
GET /oob/received
```

then submit the recovered token:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when the value matches the current editor CSRF
token.

There is **no JavaScript in this attack at all.**

## Getting Started

1. What survives the sanitiser? Post a draft with a `<script>` and an
   `<img onerror>` and see what comes back — they are gone. Now post one with a
   plain `<button>` and note it stays. What _attributes_ is that button allowed to
   keep?
2. The draft is rendered **inside** a form that has no `action`. What does HTML5
   let a `<button>` do to the form it belongs to? Where does a form with no action
   submit — and how does one button change that?
3. The editor _clicks_ your button. You do not need to steal a cookie or run any
   script — you only need the form to submit **somewhere you can read**, carrying
   what it already contains.

**CWE-79 (Improper Neutralization of Input During Web Page Generation), the
scriptless HTML-injection variant. OWASP A03:2021 – Injection.** The fix — drop
`formaction`/`formmethod` from the allow-list (and why HttpOnly and script-src CSP
do nothing here) — is in `SOLUTION.md`.

## Note on the stack

The catalogued scenario is a Node/NestJS CMS using **DOMPurify** (older permissive
config) behind nginx, reviewed by a Puppeteer bot. This lab **re-platforms it to
Flask with the nh3 allow-list sanitiser** configured with the same gap
(`<button formaction>` permitted). The lesson — an allow-list that misses
attribute _semantics_, exploited by a scriptless form-target override — is
identical on either stack. See `SOLUTION.md` for the deviation note.
