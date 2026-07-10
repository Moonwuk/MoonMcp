"""Web cache deception probe — pure variant/assess logic + fake-client end-to-end."""

import pytest

from moonmcp import server as srv
from moonmcp.web import cache_deception as cd


# -- pure helpers ------------------------------------------------------------
def test_deception_variants_shapes():
    variants = dict(cd.deception_variants("https://x.test/account"))
    urls = set(variants.values())
    assert "https://x.test/account/wcd.css" in urls
    assert "https://x.test/account;wcd.css" in urls
    assert "https://x.test/account%2fwcd.js" in urls


def test_assess_variant_confirmed_on_cached_private_leak():
    r = cd.assess_variant(auth_len=650, anon_len=5, var_status=200, var_len=650,
                          var_headers={"Age": "42", "Cache-Control": "public, max-age=60"})
    assert r is not None and r["verdict"] == "confirmed" and r["cached"] is True


def test_assess_variant_candidate_without_cache_header():
    r = cd.assess_variant(auth_len=650, anon_len=5, var_status=200, var_len=650, var_headers={})
    assert r is not None and r["verdict"] == "candidate" and r["cached"] is False


def test_assess_variant_none_when_response_is_public_sized():
    # cookieless variant returned the public/login page → not a leak
    assert cd.assess_variant(auth_len=650, anon_len=5, var_status=200, var_len=6,
                             var_headers={"Age": "42"}) is None


def test_assess_variant_none_on_non_200():
    assert cd.assess_variant(auth_len=650, anon_len=5, var_status=404, var_len=650,
                             var_headers={}) is None


# -- end-to-end with a fake client -------------------------------------------
_PRIV = "PRIVATE-DATA " * 50  # ~650 chars


class _R:
    def __init__(self, status, body, headers=None):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body
        self._h = headers or {}

    def headers_map(self):
        return dict(self._h)


class _Client:
    def __init__(self, handler):
        self._handler = handler

    async def fetch(self, url, *, suppress_auth=False, **kwargs):
        return self._handler(url, not suppress_auth)


@pytest.mark.asyncio
async def test_probe_detects_confirmed_deception():
    def handler(url, authed):
        if url.endswith("/account"):
            return _R(200, _PRIV) if authed else _R(302, "login")
        if "/account/wcd.css" in url:  # the cached variant leaks private cookieless
            return _R(200, _PRIV, {"Age": "42", "Cache-Control": "public, max-age=60"})
        return _R(404, "")
    res = await cd.probe_cache_deception(_Client(handler), "https://x.test/account")
    assert res.vulnerable is True
    assert any(f["verdict"] == "confirmed" for f in res.findings)


@pytest.mark.asyncio
async def test_probe_no_deception_when_variants_stay_private():
    def handler(url, authed):
        if url.endswith("/account"):
            return _R(200, _PRIV) if authed else _R(302, "login")
        # variants require auth too → cookieless gets the login page, no leak
        return _R(200, _PRIV) if authed else _R(302, "login")
    res = await cd.probe_cache_deception(_Client(handler), "https://x.test/account")
    assert res.vulnerable is False


@pytest.mark.asyncio
async def test_probe_bails_when_page_not_access_controlled():
    def handler(url, authed):
        return _R(200, _PRIV)  # identical authed & anon → not private
    res = await cd.probe_cache_deception(_Client(handler), "https://x.test/public")
    assert res.vulnerable is False and res.error


@pytest.mark.asyncio
async def test_cache_deception_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "cache_deception_probe" in tools
