# @websec-lab/xss-verifier

A shared **headless-Chromium victim bot** for the XSS track. It plays the role an
XSS payload needs — a victim who carries a privileged session and visits
attacker-controllable URLs — in a real browser (Playwright + Chromium), so a lab
can verify that injected JavaScript **actually executed**. You cannot grep for
"the script ran"; you need a browser to run it. This package is that browser.

One generic image serves every XSS lab. All behaviour is driven by `XSSBOT_*`
env vars, so no lab ships bot code — it just builds this context and configures
the bot in `docker-compose.yml`.

## What it does each loop

1. (optional) navigate `XSSBOT_LOGIN_URL` so the app `Set-Cookie`s the victim
   session into the browser context — the per-container secret is established at
   runtime and never baked into the image or passed through env;
2. fetch `XSSBOT_QUEUE_URL` (`{"urls":[...]}`) or use `XSSBOT_FIXED_URL` to get
   the attacker-controllable targets a `/report`-style endpoint has queued;
3. visit each target in a fresh page, lingering `XSSBOT_SETTLE_MS` so async
   payloads (`new Image().src=…`, `fetch`, `setTimeout`) fire;
4. sleep `XSSBOT_INTERVAL` and repeat.

Chromium runs with `--no-sandbox --disable-dev-shm-usage` so it works under the
lab posture (`cap_drop: ALL`, `read_only`, `no-new-privileges`, non-root). The
bot only ever visits lab-controlled origins on an internal, egress-dropped
network, so disabling the in-browser sandbox does not widen the attack surface.

## Env contract

| var                   | meaning                                                             |
| --------------------- | ------------------------------------------------------------------- |
| `XSSBOT_ORIGIN`       | **required** base origin the bot treats as home (`http://app:8080`) |
| `XSSBOT_LOGIN_URL`    | path/URL navigated each loop to (re)establish the victim session    |
| `XSSBOT_QUEUE_URL`    | JSON endpoint returning `{"urls":[...]}` of pending targets         |
| `XSSBOT_FIXED_URL`    | single target visited every loop (alternative to a queue)           |
| `XSSBOT_COOKIES`      | JSON list of cookie dicts to preload (`name`,`value`[,`url`])       |
| `XSSBOT_LOCALSTORAGE` | JSON object preloaded into `localStorage` for the origin            |
| `XSSBOT_INTERVAL`     | seconds between loops (default `2.0`)                               |
| `XSSBOT_NAV_TIMEOUT`  | per-navigation timeout, seconds (default `8.0`)                     |
| `XSSBOT_SETTLE_MS`    | ms to linger after load so async payloads fire (default `1200`)     |
| `XSSBOT_ONCE`         | run a single loop and exit (tests)                                  |
| `XSSBOT_MAX_LOOPS`    | stop after N loops (unset = forever)                                |

## Usage in a lab `docker-compose.yml`

```yaml
services:
  bot:
    build:
      context: ../../../packages/xss-verifier # each lab imports the shared package
    image: xssbot/reflected-xss-search-noescape:dev # non-`websec-lab/` = browser infra
    environment:
      XSSBOT_ORIGIN: http://app:8080
      XSSBOT_LOGIN_URL: /internal/bot-login?k=${BOT_KEY} # app Set-Cookies the admin session
      XSSBOT_QUEUE_URL: http://app:8080/internal/queue
      XSSBOT_INTERVAL: '2'
    read_only: true
    tmpfs:
      - /tmp:size=256m,mode=1777 # Chromium scratch + the /tmp/xssbot.alive heartbeat
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    healthcheck:
      test: ['CMD-SHELL', 'test -f /tmp/xssbot.alive || exit 1']
    networks: [backend]
```

The lab app exposes `XSSBOT_LOGIN_URL` (mints the victim cookie for the bot) and
`XSSBOT_QUEUE_URL` (returns URLs submitted through the lab's public `/report`
form). The payload the bot runs exfiltrates the stolen data to the lab's
in-lab OOB collector on the same internal network.

## Programmatic use

```python
from xss_verifier import Bot

Bot(
    origin="http://app:8080",
    login_url="/internal/bot-login?k=secret",
    queue_url="http://app:8080/internal/queue",
    interval=2.0,
).run(once=True)  # one loop, then return — handy in unit tests
```
