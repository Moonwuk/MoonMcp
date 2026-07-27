"""Headless-browser driver (optional, via Playwright + Chromium).

Lets the agent drive a real browser: render a JS-heavy SPA, read the post-render
DOM, run JavaScript in the page (the "browser console"), and capture the console
log, network traffic and page errors.  Consistent with MoonMCP's
"augments, never depends" philosophy — if Playwright/Chromium are absent it
returns a clear note instead of erroring.

Everything is bounded (console/network entry caps, text/HTML length caps) to keep
tool payloads small, and the engagement auth context can be applied so the SPA is
driven *authenticated*.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .screenshot import _chromium_executable, playwright_available

MAX_CHARS = 20000
MAX_CONSOLE = 150
MAX_NETWORK = 200
MAX_ERRORS = 50


async def _install_scope_guard(context, scope_ok: Callable[[str], bool],
                               extra_headers: dict[str, str] | None) -> None:
    """Route every request: abort out-of-scope navigations, and strip the engagement
    auth headers from out-of-scope subresources — so Playwright's blanket header
    application can't leak a credential to a third-party host or a redirect target."""

    auth_keys = {k.lower() for k in (extra_headers or {})}

    async def _guard(route) -> None:
        req = route.request
        try:
            in_scope = scope_ok(req.url)
        except Exception:
            in_scope = False
        try:
            if not in_scope:
                if req.is_navigation_request():
                    await route.abort()
                    return
                if auth_keys:
                    kept = {k: v for k, v in req.headers.items() if k.lower() not in auth_keys}
                    await route.continue_(headers=kept)
                    return
            await route.continue_()
        except Exception:
            try:
                await route.continue_()
            except Exception:
                pass

    try:
        await context.route("**/*", _guard)
    except Exception:
        pass


@dataclass
class BrowserResult:
    url: str
    available: bool
    final_url: str | None = None
    status: int | None = None
    title: str | None = None
    text: str | None = None
    html: str | None = None
    console: list[dict] = field(default_factory=list)
    network: list[dict] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    eval_result: object = None
    eval_error: str | None = None
    error: str | None = None
    install_hint: str | None = None


async def browse(
    url: str,
    *,
    script: str | None = None,
    capture_text: bool = True,
    capture_html: bool = False,
    wait_until: str = "load",
    timeout_ms: int = 20000,
    max_chars: int = MAX_CHARS,
    extra_headers: dict[str, str] | None = None,
    cookies: list[dict] | None = None,
    scope_ok: Callable[[str], bool] | None = None,
) -> BrowserResult:
    """Navigate a headless browser to *url*, collect observability, optionally
    evaluate a JS expression, and return a structured :class:`BrowserResult`.

    When *scope_ok* is given, out-of-scope **navigations** are aborted (so a redirect
    can't carry the engagement auth off-scope) and any engagement-auth headers are
    **stripped from out-of-scope subresource requests** — the same fail-closed scope
    discipline the HTTP tools enforce, which Playwright's blanket header application
    otherwise bypasses."""

    result = BrowserResult(url=url, available=playwright_available())
    if not result.available:
        result.error = "Playwright is not installed"
        result.install_hint = "pip install 'moonmcp[screenshots]' && playwright install chromium"
        return result

    from playwright.async_api import async_playwright  # type: ignore

    console: list[dict] = []
    network: list[dict] = []
    errors: list[str] = []

    def _on_console(msg) -> None:
        if len(console) < MAX_CONSOLE:
            console.append({"type": msg.type, "text": (msg.text or "")[:500]})

    def _on_error(exc) -> None:
        if len(errors) < MAX_ERRORS:
            errors.append(str(exc)[:500])

    def _on_response(resp) -> None:
        if len(network) < MAX_NETWORK:
            try:
                network.append({
                    "method": resp.request.method,
                    "status": resp.status,
                    "type": resp.request.resource_type,
                    "url": resp.url[:300],
                })
            except Exception:
                pass

    if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
        wait_until = "load"

    launch_kwargs: dict = {"headless": True}
    exe = _chromium_executable()
    if exe:
        launch_kwargs["executable_path"] = exe

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch_kwargs)
            try:
                context = await browser.new_context()
                if extra_headers:
                    await context.set_extra_http_headers(extra_headers)
                if scope_ok is not None:
                    await _install_scope_guard(context, scope_ok, extra_headers)
                if cookies:
                    try:
                        await context.add_cookies(cookies)
                    except Exception:
                        pass  # malformed cookie spec shouldn't sink the render
                page = await context.new_page()
                page.on("console", _on_console)
                page.on("pageerror", _on_error)
                page.on("response", _on_response)
                resp = await page.goto(url, timeout=timeout_ms, wait_until=wait_until)
                result.status = resp.status if resp else None
                result.final_url = page.url
                result.title = await page.title()
                if script:
                    try:
                        result.eval_result = await page.evaluate(script)
                    except Exception as exc:
                        result.eval_error = f"{type(exc).__name__}: {exc}"[:400]
                if capture_text:
                    try:
                        result.text = (await page.inner_text("body"))[:max_chars]
                    except Exception:
                        pass
                if capture_html:
                    try:
                        result.html = (await page.content())[:max_chars]
                    except Exception:
                        pass
            finally:
                await browser.close()
    except Exception as exc:  # launch/navigation errors must not crash the tool
        result.error = f"{type(exc).__name__}: {exc}"[:400]

    result.console = console
    result.network = network
    result.page_errors = errors
    return result


@dataclass
class InteractResult:
    url: str
    available: bool
    final_url: str | None = None
    status: int | None = None
    title: str | None = None
    text: str | None = None
    steps: list[dict] = field(default_factory=list)
    console: list[dict] = field(default_factory=list)
    network: list[dict] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    local_storage: dict = field(default_factory=dict)
    error: str | None = None
    install_hint: str | None = None


async def interact(
    url: str,
    actions: list[dict],
    *,
    timeout_ms: int = 20000,
    max_chars: int = MAX_CHARS,
    extra_headers: dict[str, str] | None = None,
    cookies: list[dict] | None = None,
    scope_ok: Callable[[str], bool] | None = None,
) -> InteractResult:
    """Drive a headless browser through a sequence of *actions* against *url* and
    return the resulting page state, storage and observability.

    Each action is a dict with an ``action`` key:
    ``click`` / ``fill`` / ``type`` (need ``selector``; fill/type need ``value``),
    ``press`` (``selector`` + ``key``), ``wait_for`` (``selector``),
    ``wait`` (``ms``), ``goto`` (``url`` — scope-checked), ``eval`` (``script``).
    """

    result = InteractResult(url=url, available=playwright_available())
    if not result.available:
        result.error = "Playwright is not installed"
        result.install_hint = "pip install 'moonmcp[screenshots]' && playwright install chromium"
        return result

    from playwright.async_api import async_playwright  # type: ignore

    console: list[dict] = []
    network: list[dict] = []
    errors: list[str] = []

    def _on_console(msg) -> None:
        if len(console) < MAX_CONSOLE:
            console.append({"type": msg.type, "text": (msg.text or "")[:500]})

    def _on_error(exc) -> None:
        if len(errors) < MAX_ERRORS:
            errors.append(str(exc)[:500])

    def _on_response(resp) -> None:
        if len(network) < MAX_NETWORK:
            try:
                network.append({"method": resp.request.method, "status": resp.status,
                                "type": resp.request.resource_type, "url": resp.url[:300]})
            except Exception:
                pass

    launch_kwargs: dict = {"headless": True}
    exe = _chromium_executable()
    if exe:
        launch_kwargs["executable_path"] = exe

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch_kwargs)
            try:
                context = await browser.new_context()
                if extra_headers:
                    await context.set_extra_http_headers(extra_headers)
                if cookies:
                    try:
                        await context.add_cookies(cookies)
                    except Exception:
                        pass
                page = await context.new_page()
                page.on("console", _on_console)
                page.on("pageerror", _on_error)
                page.on("response", _on_response)
                resp = await page.goto(url, timeout=timeout_ms, wait_until="load")
                result.status = resp.status if resp else None

                for i, act in enumerate(actions or []):
                    kind = str(act.get("action", "")).lower()
                    sel = act.get("selector")
                    step = {"i": i, "action": kind}
                    try:
                        if kind == "click":
                            await page.click(sel, timeout=timeout_ms)
                        elif kind == "fill":
                            await page.fill(sel, str(act.get("value", "")), timeout=timeout_ms)
                        elif kind == "type":
                            await page.type(sel, str(act.get("value", "")), timeout=timeout_ms)
                        elif kind == "press":
                            await page.press(sel, str(act.get("key", "Enter")), timeout=timeout_ms)
                        elif kind == "wait_for":
                            await page.wait_for_selector(sel, timeout=timeout_ms)
                        elif kind == "wait":
                            await page.wait_for_timeout(min(int(act.get("ms", 500)), 10000))
                        elif kind == "eval":
                            step["result"] = await page.evaluate(str(act.get("script", "")))
                        elif kind == "goto":
                            nxt = str(act.get("url", ""))
                            if scope_ok is not None and not scope_ok(nxt):
                                step["error"] = "out_of_scope"
                            else:
                                r2 = await page.goto(nxt, timeout=timeout_ms, wait_until="load")
                                step["status"] = r2.status if r2 else None
                        else:
                            step["error"] = f"unknown action '{kind}'"
                        step.setdefault("ok", "error" not in step)
                    except Exception as exc:
                        step["ok"] = False
                        step["error"] = f"{type(exc).__name__}: {exc}"[:300]
                    result.steps.append(step)

                result.final_url = page.url
                result.title = await page.title()
                try:
                    result.text = (await page.inner_text("body"))[:max_chars]
                except Exception:
                    pass
                try:
                    result.local_storage = await page.evaluate(
                        "Object.assign({}, window.localStorage)")
                except Exception:
                    pass
                try:
                    result.cookies = [
                        {"name": c.get("name"), "value": c.get("value"),
                         "domain": c.get("domain"), "path": c.get("path")}
                        for c in await context.cookies()
                    ]
                except Exception:
                    pass
            finally:
                await browser.close()
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"[:400]

    result.console = console
    result.network = network
    result.page_errors = errors
    return result
