# SPDX-License-Identifier: MIT
"""Headless-Chromium victim bot for XSS labs.

A `Bot` drives a real headless Chromium (via Playwright) that plays the role of
the *victim* an XSS payload needs: it carries a privileged session and visits
attacker-controllable URLs, so a payload actually executes in a browser with the
victim's cookies/localStorage. This is what makes an XSS lab verifiable — you
cannot grep for "the JavaScript ran"; you need a browser to run it.

Design goals:
  * Fully env/kwarg-driven so a single generic image serves every XSS lab
    (see `__main__.py`); no per-lab bot code.
  * The victim session is established at *runtime* by navigating a login URL the
    lab app exposes (which `Set-Cookie`s the per-container secret), so the secret
    never has to be baked into the image or passed through compose env.
  * Hardened-container friendly: Chromium runs with `--no-sandbox`
    (the setuid sandbox needs capabilities the lab drops) and
    `--disable-dev-shm-usage`, and all writable paths are tmpfs.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from playwright.sync_api import sync_playwright

DEFAULT_CHROMIUM_ARGS = [
    # The Chromium setuid sandbox requires CAP_SYS_ADMIN / user namespaces, which
    # the lab posture drops (cap_drop: ALL, no-new-privileges). The bot only ever
    # visits lab-controlled origins on an internal, egress-dropped network, so
    # disabling the in-browser sandbox does not widen the lab's attack surface.
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-setuid-sandbox",
    "--no-first-run",
    "--no-default-browser-check",
]


@dataclass
class Bot:
    origin: str
    login_url: str | None = None
    queue_url: str | None = None
    fixed_url: str | None = None
    cookies: list[dict] = field(default_factory=list)
    local_storage: dict = field(default_factory=dict)
    interval: float = 2.0
    nav_timeout: float = 8.0
    settle_ms: int = 1200
    heartbeat_path: str | None = "/tmp/xssbot.alive"
    click_selector: str | None = None
    chromium_args: list[str] = field(default_factory=lambda: list(DEFAULT_CHROMIUM_ARGS))

    def __post_init__(self) -> None:
        self.origin = self.origin.rstrip("/")

    def _abs(self, target: str) -> str:
        if target.startswith("http://") or target.startswith("https://"):
            return target
        if not target.startswith("/"):
            target = "/" + target
        return self.origin + target

    def _targets(self, ctx) -> list[str]:
        if self.fixed_url:
            return [self.fixed_url]
        if not self.queue_url:
            return []
        try:
            resp = ctx.request.get(self.queue_url, timeout=self.nav_timeout * 1000)
            if not resp.ok:
                return []
            data = resp.json()
        except Exception:  # noqa: BLE001 — a flaky queue fetch just yields no work
            return []
        items = data.get("urls") or data.get("paths") or []
        return [str(x) for x in items if x]

    def _visit(self, ctx, target: str) -> None:
        page = ctx.new_page()
        try:
            page.goto(self._abs(target), wait_until="load", timeout=self.nav_timeout * 1000)
            # Let async payloads (Image().src, fetch, setTimeout(0)) fire.
            page.wait_for_timeout(self.settle_ms)
            if self.click_selector:
                # Some labs need the victim to interact — click a javascript: link,
                # submit a formaction button. el.click() in-page activates the
                # element without Playwright's auto-wait-for-navigation.
                try:
                    page.eval_on_selector(self.click_selector, "el => el.click()")
                    page.wait_for_timeout(self.settle_ms)
                except Exception:  # noqa: BLE001 — no match / broken payload is fine
                    pass
        except Exception:  # noqa: BLE001 — a broken payload must not kill the bot
            pass
        finally:
            page.close()

    def _heartbeat(self) -> None:
        if not self.heartbeat_path:
            return
        try:
            with open(self.heartbeat_path, "w", encoding="utf-8") as fh:
                fh.write(str(time.time()))
        except OSError:
            pass

    def _establish_session(self, ctx) -> None:
        """Navigate the login URL so the app Set-Cookies the victim session into
        this browser context. Re-run each loop so a rotated session stays fresh."""
        if not self.login_url:
            return
        page = ctx.new_page()
        try:
            page.goto(self._abs(self.login_url), wait_until="load",
                      timeout=self.nav_timeout * 1000)
        except Exception:  # noqa: BLE001
            pass
        finally:
            page.close()

    def run(self, *, once: bool = False, max_loops: int | None = None) -> None:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=self.chromium_args)
            ctx = browser.new_context()
            try:
                if self.cookies:
                    ctx.add_cookies([{**c, "url": c.get("url", self.origin)} for c in self.cookies])
                if self.local_storage:
                    import json as _json
                    blob = _json.dumps(self.local_storage)
                    ctx.add_init_script(
                        "(function(){var d=%s;for(var k in d){try{localStorage.setItem(k,d[k]);}catch(e){}}})();"
                        % blob
                    )
                loops = 0
                while True:
                    self._heartbeat()
                    self._establish_session(ctx)
                    for t in self._targets(ctx):
                        self._visit(ctx, t)
                    loops += 1
                    if once or (max_loops is not None and loops >= max_loops):
                        break
                    time.sleep(self.interval)
            finally:
                ctx.close()
                browser.close()
