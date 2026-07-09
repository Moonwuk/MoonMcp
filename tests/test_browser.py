"""Tests for the headless-browser tools (browser_open / browser_eval).

Playwright is an optional dependency: when present these drive a real Chromium
against the local test server; when absent (e.g. CI without the browser) the
tools must self-degrade to a clear note. Tests branch on availability.
"""

import pytest

from moonmcp import server as srv
from moonmcp.web import browser as browsermod

_HAVE = browsermod.playwright_available()
_skip_live = pytest.mark.skipif(not _HAVE, reason="Playwright/Chromium not installed")


@pytest.mark.asyncio
async def test_browser_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "browser_open" in tools and "browser_eval" in tools


@pytest.mark.asyncio
async def test_browser_degrades_without_playwright(monkeypatch, fresh_context):
    monkeypatch.setattr(browsermod, "playwright_available", lambda: False)
    res = await srv.browser_open(target="http://127.0.0.1:1/")
    assert res["available"] is False
    assert "not installed" in (res.get("error") or "")
    assert res.get("install_hint")


@_skip_live
@pytest.mark.asyncio
async def test_browser_open_live(local_server, fresh_context):
    base, _ = local_server
    res = await srv.browser_open(target=base, capture_html=True)
    assert res["available"] is True
    assert res["status"] == 200
    assert res["title"] == "Local"
    assert "hello" in (res.get("text") or "").lower()
    assert res.get("html")
    # the main document request should show up in the captured network traffic
    assert any(n.get("type") == "document" or "127.0.0.1" in n.get("url", "")
               for n in res.get("network", []))


@_skip_live
@pytest.mark.asyncio
async def test_browser_eval_live(local_server, fresh_context):
    base, _ = local_server
    # run JS in the page: console.log is captured and the expression value returned
    res = await srv.browser_eval(target=base, script="console.log('probe-xyz'); 6*7")
    assert res["eval_result"] == 42
    assert any("probe-xyz" in c.get("text", "") for c in res.get("console", []))
    # DOM access works too
    res2 = await srv.browser_eval(target=base, script="document.title")
    assert res2["eval_result"] == "Local"


@_skip_live
@pytest.mark.asyncio
async def test_browser_eval_error_is_structured(local_server, fresh_context):
    base, _ = local_server
    res = await srv.browser_eval(target=base, script="throw new Error('boom-eval')")
    assert res.get("eval_result") is None
    assert "boom-eval" in (res.get("eval_error") or "")


@pytest.mark.asyncio
async def test_browser_interact_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "browser_interact" in tools


@_skip_live
@pytest.mark.asyncio
async def test_browser_interact_flow(local_server, fresh_context):
    base, _ = local_server
    res = await srv.browser_interact(target=f"{base}/app", actions=[
        {"action": "fill", "selector": "#q", "value": "hello"},
        {"action": "click", "selector": "#go"},
        {"action": "wait_for", "selector": "#out"},
        {"action": "eval", "script": "document.getElementById('out').innerText"},
    ])
    assert res["available"] is True
    assert all(s.get("ok") for s in res["steps"]), res["steps"]
    # the click ran the inline JS → localStorage + console + DOM update
    assert res["local_storage"].get("token") == "t0ken"
    assert any("go-clicked" in c.get("text", "") for c in res["console"])
    assert res["steps"][-1].get("result") == "clicked:hello"
    # an out-of-scope goto step is refused, not followed
    res2 = await srv.browser_interact(target=f"{base}/app", actions=[
        {"action": "goto", "url": "http://evil.example.test/"},
    ])
    assert res2["steps"][0].get("error") == "out_of_scope"
