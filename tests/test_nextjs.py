"""Next.js middleware auth-bypass (CVE-2025-29927) — pure differential + gated-route probe."""

import pytest

from moonmcp import server as srv
from moonmcp.web import nextjs as nx


# -- pure helpers ------------------------------------------------------------
def test_is_nextjs_fingerprint():
    assert nx.is_nextjs({"X-Powered-By": "Next.js"}, "")            # case-insensitive header
    assert nx.is_nextjs({"x-nextjs-cache": "HIT"}, "")
    assert nx.is_nextjs({}, '<script id="__NEXT_DATA__">{}</script>')
    assert nx.is_nextjs({}, '<link href="/_next/static/x.css">')
    assert not nx.is_nextjs({"Server": "nginx"}, "<html>plain</html>")


def test_is_gated_and_gate_kind():
    assert nx.is_gated(401, {}) and nx.is_gated(403, {}) and nx.is_gated(307, {})
    assert not nx.is_gated(200, {}) and not nx.is_gated(404, {})
    assert nx.gate_kind(401, {}) == "auth"
    assert nx.gate_kind(307, {"Location": "/login?next=/x"}) == "auth"
    assert nx.gate_kind(302, {"Location": "/account/sso"}) == "auth"
    assert nx.gate_kind(308, {"Location": "/en-us/home"}) == "redirect"   # locale, not auth


def test_opened():
    assert nx.opened(307, 200) and nx.opened(401, 204)
    assert not nx.opened(200, 200)          # baseline not gated
    assert not nx.opened(307, 302)          # still gated
    assert not nx.opened(307, None)


def test_payloads_cover_versions():
    assert nx.HEADER == "x-middleware-subrequest"
    # the repeated-path form (defeats the Next 13.2–15 recursion counter) is present
    assert any(":" in p and p.count("middleware") >= 5 for p in nx.BYPASS_PAYLOADS)
    assert "pages/_middleware" in nx.BYPASS_PAYLOADS   # Next 12 layout


# -- gated-route integration -------------------------------------------------
@pytest.mark.asyncio
async def test_probe_confirms_auth_gate_bypass(local_server, fresh_context):
    base, _ = local_server
    res = await srv.nextjs_middleware_probe(target=f"{base}/nextjs-gated")
    assert res["verdict"] == "confirmed", res
    assert res["is_nextjs"] is True
    f = res["findings"][0]
    assert f["severity"] == "high" and f["gate"] == "auth"
    assert f["baseline_status"] == 307 and 200 <= f["bypassed_status"] < 300
    assert res["suggested_next"]


@pytest.mark.asyncio
async def test_probe_not_gated_route(local_server, fresh_context):
    base, _ = local_server
    res = await srv.nextjs_middleware_probe(target=f"{base}/nextjs-open")
    assert res["verdict"] == "not_gated" and not res["findings"]


@pytest.mark.asyncio
async def test_probe_patched_gate_holds(local_server, fresh_context):
    base, _ = local_server
    res = await srv.nextjs_middleware_probe(target=f"{base}/nextjs-patched")
    assert res["verdict"] == "not_vulnerable" and not res["findings"]


@pytest.mark.asyncio
async def test_nextjs_middleware_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "nextjs_middleware_probe" in tools
