# Track charter — Cross-Site Scripting (`xss`)

26 labs in `data/catalog.json`. The track walks the XSS arc — reflected → stored
→ DOM, then filter/sanitiser bypasses, framework-specific sinks (jQuery, AngularJS,
Vue), client-side trust boundaries (postMessage, CSP, mXSS), and finally
multi-step chains (CSRF→self-XSS, cache-poisoning mass-XSS, nonce leaks).

Flag contract for every lab: `FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") }`,
written at container start by `entrypoint.sh` and gated behind the intended vuln.

## The victim-bot model (shared infrastructure)

XSS is not verifiable by grepping a response — the payload has to **run in a
browser**. Every XSS lab that needs a victim uses the shared
[`@websec-lab/xss-verifier`](../../packages/xss-verifier/README.md) package: a
generic, env-driven **headless-Chromium bot** (Playwright, Python). A lab builds
the bot from that package context (`build.context: ../../../packages/xss-verifier`)
and configures it purely through `XSSBOT_*` env — no per-lab bot code.

Standard lab shape:

- **app** — the vulnerable Flask service. The size-gated `websec-lab/<slug>` image
  (< 300 MB, Trivy-scanned).
- **bot** — the shared victim bot. Tagged `xssbot/<slug>` (not `websec-lab/`)
  because a browser is **infra**, like a pulled DB engine — large, not the lab
  app, so not size/Trivy-gated. It **is** posture-gated (non-root, `read_only`,
  `cap_drop: ALL`, `no-new-privileges`): Chromium runs `--no-sandbox
--disable-dev-shm-usage` with a tmpfs `/tmp`.
- **collector** — the in-lab OOB listener (stdlib `http.server`, reused from the
  SQLi OOB labs). On the `backend` network (`internal: true`, egress-drop), so a
  stolen cookie/token can reach the collector but **never the internet**. The app
  proxies it via `GET /oob/received`.

The admin bot establishes its privileged session at runtime by navigating an
`/internal/bot-login` endpoint the app firewalls to the backend subnet, so the
per-container secret is never baked into the image or passed through env, and a
lab visitor on the public side cannot fetch the admin cookie to skip the XSS.

Because the app image stays small and Chromium headless runs fine in CI, XSS labs
are **standard-tier** (PR-gated), not heavy — the browser is a pulled base, like a
DB engine, not a size-capped build.

## Implemented

### batch/track-xss-a-reflected (this batch — shared verifier + first lab)

- **`packages/xss-verifier`** — the shared victim-bot package described above
  (Playwright headless Chromium, env-driven, one generic image per lab).
- `reflected-xss-search-noescape` (**apprentice**) — reflected XSS: a bookshop
  echoes `?q=` into the results heading through an autoescape-disabled Jinja
  render. A payload submitted via `POST /report` runs in the admin bot's browser,
  reads its non-HttpOnly `session` cookie, and beacons it to the collector; the
  learner reads it back through `GET /oob/received` and `POST /solve`s it. Teaches
  the reflected sink, the victim-delivery model, OOB exfil, and the two
  independent fixes (output encoding + HttpOnly). `risk: low` — egress-dropped
  backend contains the cookie-theft primitive.

## Scheduled (from `data/catalog.json`)

Reflected (done: 1) → stored → DOM → filter-ladder/sanitiser bypass →
framework sinks (jQuery/AngularJS/Vue) → client-side trust boundaries
(postMessage/CSP/mXSS/DOMPurify) → multi-step chains (self-XSS+CSRF,
dangling-markup, cache-poison mass-XSS, nonce-leak). ~6 labs per batch.
