"""Guard failure control flow plus actual Chromium HTTP boundary observations."""

import http.server
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import pytest

from moonmcp.web import browser


async def test_registration_failure_is_not_swallowed():
    context = SimpleNamespace(route=AsyncMock(side_effect=RuntimeError("registration failed")))
    with pytest.raises(RuntimeError, match="registration failed"):
        await browser._install_scope_guard(context, lambda _: True, None)


async def test_abort_failure_closes_context_without_continuation():
    context = SimpleNamespace(route=AsyncMock(), close=AsyncMock())
    errors = await browser._install_scope_guard(context, lambda _: False, None)
    handler = context.route.call_args.args[1]
    route = SimpleNamespace(request=SimpleNamespace(url="https://outside.test/"),
                            abort=AsyncMock(side_effect=RuntimeError("abort failed")),
                            continue_=AsyncMock(), fetch=AsyncMock())
    with pytest.raises(RuntimeError, match="abort failed"):
        await handler(route)
    route.continue_.assert_not_called()
    route.fetch.assert_not_called()
    context.close.assert_awaited_once()
    assert "scope_guard_failed" in errors


async def test_scope_predicate_failure_never_sends():
    def broken(url):
        raise RuntimeError("predicate failed")
    context = SimpleNamespace(route=AsyncMock(), close=AsyncMock())
    errors = await browser._install_scope_guard(context, broken, None)
    route = SimpleNamespace(request=SimpleNamespace(url="https://fixture.test/"),
                            abort=AsyncMock(), continue_=AsyncMock(), fetch=AsyncMock())
    await context.route.call_args.args[1](route)
    route.fetch.assert_not_called()
    route.continue_.assert_not_called()
    assert errors == ["scope_guard_failed"]


@pytest.fixture
def boundary_servers():
    seen = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.server.server_port, self.path, self.headers.get("Authorization")))
            if self.path.startswith("/redirect"):
                self.send_response(302)
                destination = allowed if self.path == "/redirect-allowed" else forbidden
                self.send_header("Location", destination + "/landing")
                body = b""
            else:
                self.send_response(200)
                body = (f'<html><title>fixture</title><body>normal use'
                        f'<a id="escape" href="{forbidden}/clicked">escape</a>'
                        f'<img src="{forbidden}/pixel">'
                        '<a id="normal" href="/landing">normal</a></body></html>').encode()
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

    servers = [http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) for _ in range(2)]
    allowed, forbidden = [f"http://127.0.0.1:{s.server_port}" for s in servers]
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()
    try:
        yield allowed, forbidden, seen
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


_live = pytest.mark.skipif(not browser.playwright_available(), reason="Playwright not installed")


@_live
@pytest.mark.parametrize("mode", ["browse", "interact"])
async def test_live_redirect_subresource_and_click_never_reach_forbidden_host(boundary_servers, mode):
    allowed, forbidden, seen = boundary_servers
    def scope(url):
        return urlsplit(url).netloc == urlsplit(allowed).netloc
    headers = {"Authorization": "Bearer synthetic-fixture"}
    if mode == "browse":
        result = await browser.browse(allowed + "/redirect", scope_ok=scope, extra_headers=headers)
        assert result.error
    else:
        result = await browser.interact(allowed, [
            {"action": "click", "selector": "#normal"},
            {"action": "click", "selector": "#escape"},
        ], scope_ok=scope, extra_headers=headers, timeout_ms=3000)
        assert result.steps[0]["ok"]
        assert result.error
    assert seen
    assert all(port != urlsplit(forbidden).port for port, _, _ in seen)
    assert any(token == "Bearer synthetic-fixture" for _, _, token in seen)


@_live
async def test_live_allowed_redirect_still_renders(boundary_servers):
    allowed, _, seen = boundary_servers
    result = await browser.browse(allowed + "/redirect-allowed",
                                  scope_ok=lambda url: urlsplit(url).netloc == urlsplit(allowed).netloc)
    assert result.status == 200
    assert result.title == "fixture"
    assert "normal use" in result.text
    assert any(path == "/landing" for _, path, _ in seen)


@_live
@pytest.mark.parametrize("mode", ["browse", "interact"])
async def test_live_registration_failure_prevents_initial_navigation(monkeypatch, boundary_servers, mode):
    allowed, _, seen = boundary_servers
    async def fail(*args, **kwargs):
        raise RuntimeError("guard installation failed")
    monkeypatch.setattr(browser, "_install_scope_guard", fail)
    result = (await browser.browse(allowed, scope_ok=lambda _: True) if mode == "browse"
              else await browser.interact(allowed, [], scope_ok=lambda _: True))
    assert "guard installation failed" in result.error
    assert seen == []
