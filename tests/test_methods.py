"""HTTP method probing — catch-all baseline + XST reflection guards."""

import pytest

from moonmcp.web import methods as mm


class _R:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self.body = body if isinstance(body, bytes) else body.encode()
        self._h = {k.lower(): v for k, v in (headers or {}).items()}

    def text(self, limit=None):
        return self.body.decode("utf-8", "replace")

    def header(self, name):
        return self._h.get(name.lower())


class _Client:
    def __init__(self, fn):
        self._fn = fn

    async def fetch(self, url, *, method="GET", headers=None, **kw):
        return self._fn(url, method, headers or {})


@pytest.mark.asyncio
async def test_catch_all_host_no_false_put_enabled():
    # Every method on any path returns the same 200 SPA page → nothing is "enabled".
    res = await mm.check_methods(_Client(lambda u, m, h: _R(200, b"<html>app</html>")),
                                 "https://spa.test/")
    assert res.risky_enabled == []


@pytest.mark.asyncio
async def test_real_put_enabled_flagged():
    def fn(url, method, headers):
        if ".nonexistent" in url and method == "GET":
            return _R(404, b"not found")            # host 404s unknown paths (not catch-all)
        if method == "PUT":
            return _R(201, b"created")
        if method == "OPTIONS":
            return _R(200, b"", {"Allow": "GET, PUT"})
        return _R(405, b"")
    res = await mm.check_methods(_Client(fn), "https://x.test/")
    assert "PUT" in res.risky_enabled


@pytest.mark.asyncio
async def test_trace_word_in_html_is_not_xst():
    # The word 'trace' in a normal page must not read as Cross-Site Tracing.
    def fn(url, method, headers):
        if method == "TRACE":
            return _R(200, b"<html>Error: see stack trace for details</html>")
        return _R(404, b"")
    res = await mm.check_methods(_Client(fn), "https://x.test/")
    assert "TRACE" not in res.risky_enabled


@pytest.mark.asyncio
async def test_real_xst_reflects_marker_header():
    def fn(url, method, headers):
        if method == "TRACE":
            echo = "TRACE / HTTP/1.1\r\nX-Moonmcp-Xst: " + headers.get("X-Moonmcp-Xst", "") + "\r\n"
            return _R(200, echo.encode(), {"Content-Type": "message/http"})
        return _R(404, b"")
    res = await mm.check_methods(_Client(fn), "https://x.test/")
    assert "TRACE" in res.risky_enabled
