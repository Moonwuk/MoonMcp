"""Detection eval harness — run each active detector against a deliberately
vulnerable endpoint and assert it detects the planted vuln.

This is a measurable recall check (and a regression guard): if a probe stops
detecting its class, this fails. The vulnerable endpoints live in conftest's
local server (/ssti, /sqli, /ssrf, /cache).
"""

import pytest

from moonmcp import server as srv


@pytest.mark.asyncio
async def test_ssti_probe_detects_jinja(local_server, fresh_context):
    base, _ = local_server
    res = await srv.ssti_probe(target=f"{base}/ssti", param="name")
    assert res["verdict"] == "confirmed"
    engines = {e["engine"] for e in res["engines"]}
    assert any("Jinja2" in e for e in engines), res


@pytest.mark.asyncio
async def test_ssti_probe_no_false_positive(local_server, fresh_context):
    # /reflect echoes the param verbatim but does NOT evaluate templates.
    base, _ = local_server
    res = await srv.ssti_probe(target=f"{base}/reflect", param="name")
    assert res["verdict"] == "unconfirmed"
    assert res["engines"] == []


@pytest.mark.asyncio
async def test_sqli_probe_detects(local_server, fresh_context):
    base, _ = local_server
    res = await srv.sqli_probe(target=f"{base}/sqli", param="q")
    assert any(h["class"] == "sqli" for h in res["error_signatures"])
    assert res["boolean_differential"] is True
    assert res["verdict"] in ("likely", "confirmed")


@pytest.mark.asyncio
async def test_ssrf_probe_confirms_via_selfhost(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.ssrf_probe(target=f"{base}/ssrf", param="url", wait=1.0)
        assert res["verdict"] == "confirmed", res
        assert res["interactions"], res
    finally:
        await srv.oast_selfhost(action="stop")


@pytest.mark.asyncio
async def test_cache_probe_detects_unkeyed_reflection(local_server, fresh_context):
    base, _ = local_server
    res = await srv.cache_probe(target=f"{base}/cache")
    assert res["cacheable"] is True
    headers = {r["header"] for r in res["unkeyed_reflection"]}
    assert "X-Forwarded-Host" in headers
    assert res["verdict"] == "likely"


@pytest.mark.asyncio
async def test_probes_are_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    for res in (
        await srv.ssti_probe(target=f"{base}/ssti", param="name"),
        await srv.sqli_probe(target=f"{base}/sqli", param="q"),
        await srv.cache_probe(target=f"{base}/cache"),
    ):
        assert res["error"] == "disabled"
