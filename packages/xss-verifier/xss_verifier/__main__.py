# SPDX-License-Identifier: MIT
"""CLI entrypoint: `python -m xss_verifier`.

A single generic image drives every XSS lab; all behaviour comes from env vars so
no per-lab bot code is needed. Required: XSSBOT_ORIGIN. Everything else optional.

  XSSBOT_ORIGIN        base origin the bot treats as home, e.g. http://app:8080
  XSSBOT_LOGIN_URL     path/URL navigated each loop so the app Set-Cookies the
                       victim session into the browser (e.g. /internal/bot-login?k=...)
  XSSBOT_QUEUE_URL     JSON endpoint returning {"urls":[...]} of pending targets
  XSSBOT_FIXED_URL     visit this single target every loop (alternative to a queue)
  XSSBOT_COOKIES       JSON list of cookie dicts to preload (name,value[,url])
  XSSBOT_LOCALSTORAGE  JSON object preloaded into localStorage for the origin
  XSSBOT_INTERVAL      seconds between loops (default 2.0)
  XSSBOT_NAV_TIMEOUT   per-navigation timeout seconds (default 8.0)
  XSSBOT_SETTLE_MS     ms to linger after load so async payloads fire (default 1200)
  XSSBOT_CLICK_SELECTOR after settling, click the first element matching this CSS
                       selector (activates javascript: links / submits formaction buttons)
  XSSBOT_ONCE          if set, run a single loop and exit (used by tests)
  XSSBOT_MAX_LOOPS     stop after N loops (unset = forever)
"""
from __future__ import annotations

import json
import os
import sys

from .bot import Bot


def _json_env(name: str, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except ValueError:
        print(f"[xss-verifier] {name} is not valid JSON, ignoring", file=sys.stderr)
        return default


def main() -> int:
    origin = os.environ.get("XSSBOT_ORIGIN")
    if not origin:
        print("[xss-verifier] XSSBOT_ORIGIN is required", file=sys.stderr)
        return 2

    bot = Bot(
        origin=origin,
        login_url=os.environ.get("XSSBOT_LOGIN_URL") or None,
        queue_url=os.environ.get("XSSBOT_QUEUE_URL") or None,
        fixed_url=os.environ.get("XSSBOT_FIXED_URL") or None,
        cookies=_json_env("XSSBOT_COOKIES", []),
        local_storage=_json_env("XSSBOT_LOCALSTORAGE", {}),
        interval=float(os.environ.get("XSSBOT_INTERVAL", "2.0")),
        nav_timeout=float(os.environ.get("XSSBOT_NAV_TIMEOUT", "8.0")),
        settle_ms=int(os.environ.get("XSSBOT_SETTLE_MS", "1200")),
        click_selector=os.environ.get("XSSBOT_CLICK_SELECTOR") or None,
    )
    max_loops = os.environ.get("XSSBOT_MAX_LOOPS")
    bot.run(
        once=bool(os.environ.get("XSSBOT_ONCE")),
        max_loops=int(max_loops) if max_loops else None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
