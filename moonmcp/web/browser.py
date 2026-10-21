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
from urllib.parse import urljoin, urlsplit

from .browser_runtime import BrowserEvaluationTimeout, evaluate, run_session
from .browser_safety import screen_result
from .screenshot import _chromium_executable, playwright_available

MAX_CHARS = 20000
MAX_CONSOLE = 150
MAX_NETWORK = 200
MAX_ERRORS = 50
MAX_ACTIONS = 100
WALL_TIMEOUT_MS = 60000


async def _install_scope_guard(context, scope_ok: Callable[[str], bool],
                               extra_headers: dict[str, str] | None,
                               *, credential_url: str | None = None) -> list[str]:
    """Fail closed for routed HTTP, including redirects and subresources.

    Fetch without automatic redirects so a redirect cannot bypass routing or
    forward blanket context credentials. Authenticated contexts stay on their
    initial origin. Failures are retained even if a page catches a failed fetch.
    This does not make browser traffic a managed/metered transport.
    """
    failures: list[str] = []

    def allowed(url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not scope_ok(url):
            return False
        if credential_url:
            initial = urlsplit(credential_url)
            if (parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)) != (
                    initial.scheme, initial.hostname, initial.port or (443 if initial.scheme == "https" else 80)):
                return False
        return True

    def record(reason: str) -> None:
        if len(failures) < MAX_ERRORS:
            failures.append(reason)

    async def _guard(route) -> None:
        try:
            if not allowed(route.request.url):
                record("out_of_scope")
                await route.abort()
                return
            response = await route.fetch(max_redirects=0, timeout=20000)
            try:
                location = response.headers.get("location")
                if 300 <= response.status < 400 and location and not allowed(urljoin(route.request.url, location)):
                    record("out_of_scope_redirect")
                    await route.abort()
                    return
                await route.fulfill(response=response)
            finally:
                await response.dispose()
        except Exception:
            record("scope_guard_failed")
            try:
                await route.abort()
            finally:
                await context.close()

    # Registration errors must propagate before creating a page or navigating.
    await context.route("**/*", _guard)
    return failures


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
    trust: str = "untrusted"
    content_safety: dict = field(default_factory=dict)
    cleanup_confirmed: bool | None = None
    cleanup_error: str | None = None


async def browse(
    url: str,
    *,
    script: str | None = None,
    capture_text: bool = True,
    capture_html: bool = False,
    wait_until: str = "load",
    timeout_ms: int = 20000,
    wall_timeout_ms: int = WALL_TIMEOUT_MS,
    max_chars: int = MAX_CHARS,
    extra_headers: dict[str, str] | None = None,
    cookies: list[dict] | None = None,
    scope_ok: Callable[[str], bool] | None = None,
) -> BrowserResult:
    """Navigate a headless browser to *url*, collect observability, optionally
    evaluate a JS expression, and return a structured :class:`BrowserResult`.

    With *scope_ok*, routed HTTP requests and redirects outside scope are blocked.
    Contexts with supplied credentials are restricted to the initial origin."""

    result = BrowserResult(url=url, available=playwright_available())
    if (not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool)
            or not 1 <= timeout_ms <= 120000
            or not isinstance(wall_timeout_ms, int) or isinstance(wall_timeout_ms, bool)
            or not 1 <= wall_timeout_ms <= 120000):
        result.error = "timeout_ms and wall_timeout_ms must be between 1 and 120000"
        return screen_result(result)
    if not result.available:
        result.error = "Playwright is not installed"
        result.install_hint = "pip install 'moonmcp[screenshots]' && playwright install chromium"
        return screen_result(result)

    from playwright.async_api import async_playwright  # type: ignore

    console: list[dict] = []
    network: list[dict] = []
    errors: list[str] = []
    guard_failures: list[str] = []

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

    async def _operation(browser) -> None:
        nonlocal guard_failures
        context = await browser.new_context(ignore_https_errors=True, service_workers="block")
        if extra_headers:
            await context.set_extra_http_headers(extra_headers)
        if scope_ok is not None:
            guard_failures = await _install_scope_guard(
                context, scope_ok, extra_headers,
                credential_url=url if extra_headers or cookies else None)
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
                result.eval_result = await evaluate(page, script, timeout_ms)
            except BrowserEvaluationTimeout as exc:
                result.eval_error = f"{type(exc).__name__}: {exc}"[:400]
                raise
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

    try:
        await run_session(result, async_playwright, launch_kwargs, _operation, wall_timeout_ms)
    except Exception as exc:  # launch/navigation errors must not crash the tool
        result.error = f"{type(exc).__name__}: {exc}"[:400]

    result.console = console
    result.network = network
    result.page_errors = errors
    if guard_failures:
        result.error = result.error or f"Browser request guard: {', '.join(sorted(set(guard_failures)))}"
    return screen_result(result)


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
    trust: str = "untrusted"
    content_safety: dict = field(default_factory=dict)
    cleanup_confirmed: bool | None = None
    cleanup_error: str | None = None


async def interact(
    url: str,
    actions: list[dict],
    *,
    timeout_ms: int = 20000,
    wall_timeout_ms: int = WALL_TIMEOUT_MS,
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
    if (not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool)
            or not 1 <= timeout_ms <= 120000
            or not isinstance(wall_timeout_ms, int) or isinstance(wall_timeout_ms, bool)
            or not 1 <= wall_timeout_ms <= 120000):
        result.error = "timeout_ms and wall_timeout_ms must be between 1 and 120000"
        return screen_result(result)
    if len(actions or []) > MAX_ACTIONS:
        result.error = f"At most {MAX_ACTIONS} browser actions are allowed"
        return screen_result(result)
    if not result.available:
        result.error = "Playwright is not installed"
        result.install_hint = "pip install 'moonmcp[screenshots]' && playwright install chromium"
        return screen_result(result)

    from playwright.async_api import async_playwright  # type: ignore

    console: list[dict] = []
    network: list[dict] = []
    errors: list[str] = []
    guard_failures: list[str] = []

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

    async def _operation(browser) -> None:
        nonlocal guard_failures
        context = await browser.new_context(ignore_https_errors=True, service_workers="block")
        if extra_headers:
            await context.set_extra_http_headers(extra_headers)
        if scope_ok is not None:
            guard_failures = await _install_scope_guard(
                context, scope_ok, extra_headers,
                credential_url=url if extra_headers or cookies else None)
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
                    step["result"] = await evaluate(page, str(act.get("script", "")), timeout_ms)
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
            except BrowserEvaluationTimeout as exc:
                step["ok"] = False
                step["error"] = f"{type(exc).__name__}: {exc}"[:300]
                result.steps.append(step)
                raise
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
            result.local_storage = await evaluate(
                page, "Object.assign({}, window.localStorage)", timeout_ms)
        except BrowserEvaluationTimeout:
            raise
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

    try:
        await run_session(result, async_playwright, launch_kwargs, _operation, wall_timeout_ms)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"[:400]

    result.console = console
    result.network = network
    result.page_errors = errors
    if guard_failures:
        result.error = result.error or f"Browser request guard: {', '.join(sorted(set(guard_failures)))}"
    return screen_result(result)
