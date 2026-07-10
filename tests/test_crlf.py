"""CRLF injection / response-splitting probe."""

import pytest

from moonmcp import server as srv
from moonmcp.web import crlf


# -- pure helpers ------------------------------------------------------------
def test_inject_raw_appends_without_reencoding():
    # the %0d%0a must stay literal (not become %250d%250a)
    u = crlf.inject_raw("https://x.test/p?a=1", "q", "v%0d%0aX-Moonmcp-Inj:1")
    assert u == "https://x.test/p?a=1&q=v%0d%0aX-Moonmcp-Inj:1"
    u2 = crlf.inject_raw("https://x.test/p", "q", "v%0aX")
    assert u2 == "https://x.test/p?q=v%0aX"


def test_assess_detects_marker_header_and_cookie():
    assert crlf.assess({"X-Moonmcp-Inj": "1"}, []) is True
    assert crlf.assess({}, ["moonmcpcrlf=1; Path=/"]) is True
    assert crlf.assess({"Content-Type": "text/html"}, ["sid=abc"]) is False


# -- end-to-end with a fake client -------------------------------------------
class _R:
    def __init__(self, status, headers=None, set_cookies=None):
        self.status = status
        self._h = headers or {}
        self._sc = set_cookies or []

    def headers_map(self):
        return dict(self._h)

    def get_all(self, name):
        return self._sc if name.lower() == "set-cookie" else []

    def text(self, limit=None):
        return ""


class _Client:
    def __init__(self, handler):
        self._handler = handler

    async def fetch(self, url, **kwargs):
        return self._handler(url)


@pytest.mark.asyncio
async def test_probe_confirms_header_injection():
    # a vulnerable server reflects the CRLF into a real header
    def handler(url):
        if "X-Moonmcp-Inj:1" in url:
            return _R(200, headers={"X-Moonmcp-Inj": "1"})
        return _R(200)
    res = await crlf.probe_crlf(_Client(handler), "https://x.test/r", "url")
    assert res and res[0]["verdict"] == "confirmed"


@pytest.mark.asyncio
async def test_probe_confirms_cookie_split():
    def handler(url):
        if "Set-Cookie:moonmcpcrlf=1" in url:
            return _R(200, set_cookies=["moonmcpcrlf=1; Path=/"])
        return _R(200)
    res = await crlf.probe_crlf(_Client(handler), "https://x.test/r", "next")
    assert res and "response splitting" in res[0]["detail"]


@pytest.mark.asyncio
async def test_probe_safe_param_no_findings():
    # server reflects into BODY only (not a header) → not vulnerable
    res = await crlf.probe_crlf(_Client(lambda url: _R(200, headers={"Content-Type": "text/html"})),
                                "https://x.test/r", "q")
    assert res == []


@pytest.mark.asyncio
async def test_crlf_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "crlf_probe" in tools
