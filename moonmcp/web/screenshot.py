"""Optional page screenshotting via Playwright + Chromium.

Consistent with MoonMCP's "augments, never depends" philosophy: if Playwright and
a Chromium build are present, capture a real rendered screenshot; if not, return
a clear, actionable note instead of erroring.  Screenshots are written to disk
(base64 is returned only on request, to keep tool payloads small).
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass


@dataclass
class ScreenshotResult:
    url: str
    available: bool
    path: str | None = None
    width: int | None = None
    height: int | None = None
    title: str | None = None
    final_url: str | None = None
    status: int | None = None
    image_base64: str | None = None
    error: str | None = None
    install_hint: str | None = None


def playwright_available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
        return True
    except Exception:
        return False


def _chromium_executable() -> str | None:
    """Honour a pre-provisioned Chromium (e.g. PLAYWRIGHT_BROWSERS_PATH env)."""

    explicit = os.environ.get("MOONMCP_CHROMIUM_PATH")
    if explicit and os.path.exists(explicit):
        return explicit
    # A common managed layout: /opt/pw-browsers/chromium
    guess = os.path.join(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""), "chromium")
    return guess if guess and os.path.exists(guess) else None


async def capture(
    url: str,
    *,
    out_dir: str,
    full_page: bool = True,
    width: int = 1280,
    height: int = 800,
    timeout_ms: int = 20000,
    return_base64: bool = False,
) -> ScreenshotResult:
    result = ScreenshotResult(url=url, available=playwright_available())
    if not result.available:
        result.error = "Playwright is not installed"
        result.install_hint = "pip install playwright && playwright install chromium"
        return result

    from playwright.async_api import async_playwright  # type: ignore

    os.makedirs(out_dir, exist_ok=True)
    fname = hashlib.sha256(url.encode()).hexdigest()[:16] + ".png"
    path = os.path.join(out_dir, fname)

    launch_kwargs: dict = {"headless": True}
    exe = _chromium_executable()
    if exe:
        launch_kwargs["executable_path"] = exe

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch_kwargs)
            try:
                page = await browser.new_page(viewport={"width": width, "height": height})
                resp = await page.goto(url, timeout=timeout_ms, wait_until="load")
                result.status = resp.status if resp else None
                result.final_url = page.url
                result.title = await page.title()
                await page.screenshot(path=path, full_page=full_page)
            finally:
                await browser.close()
    except Exception as exc:  # navigation/render errors shouldn't crash the tool
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    result.path = path
    try:
        result.width, result.height = width, height
        if return_base64:
            with open(path, "rb") as fh:
                result.image_base64 = base64.b64encode(fh.read()).decode()
    except OSError as exc:
        result.error = f"screenshot saved but unreadable: {exc}"
    return result
