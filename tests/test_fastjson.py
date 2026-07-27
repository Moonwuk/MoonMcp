"""Fastjson/Jackson autoType OAST probe — pure payloads + OAST-correlated eval."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.web import fastjson as fj


def test_fastjson_payloads():
    payloads = dict(fj.fastjson_payloads("cnry.oast.test", "http://cnry.oast.test/t"))
    assert set(payloads) == {"fastjson-inetaddress", "fastjson-url",
                             "fastjson-url-hashcode", "jackson-url"}
    inet = json.loads(payloads["fastjson-inetaddress"])
    assert inet["@type"] == "java.net.Inet4Address" and inet["val"] == "cnry.oast.test"
    url = json.loads(payloads["fastjson-url"])
    assert url["@type"] == "java.net.URL" and url["val"] == "http://cnry.oast.test/t"
    assert json.loads(payloads["jackson-url"]) == ["java.net.URL", "http://cnry.oast.test/t"]


@pytest.mark.asyncio
async def test_fastjson_probe_confirms_via_selfhost(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.fastjson_oast_probe(target=f"{base}/fastjson", wait=1.5)
        assert res["verdict"] == "confirmed", res
        assert res["interactions"] and len(res["payloads_sent"]) == 4
    finally:
        await srv.oast_selfhost(action="stop")


@pytest.mark.asyncio
async def test_fastjson_probe_unconfigured_oast(local_server, fresh_context):
    base, _ = local_server
    res = await srv.fastjson_oast_probe(target=f"{base}/fastjson")
    assert res["error"] == "oast_unconfigured"


@pytest.mark.asyncio
async def test_fastjson_probe_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.fastjson_oast_probe(target=f"{base}/fastjson")
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_fastjson_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "fastjson_oast_probe" in tools
