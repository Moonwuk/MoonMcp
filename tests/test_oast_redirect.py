"""Tests for OAST callback tooling and the redirect tracer."""

import pytest

from moonmcp import server as srv
from moonmcp.intel import oast as oastmod


def test_oast_store_unit():
    s = oastmod.OastStore()
    assert not s.configured
    cb = s.generate(label="ssrf on /import")
    assert len(cb.token) >= 12 and cb.canary_host is None
    s.configure(interaction_domain="oast.example.net", poll_url="https://oast.example.net/poll?id={token}")
    assert s.configured
    cb2 = s.generate(label="xxe")
    assert cb2.canary_host == f"{cb2.token}.oast.example.net"
    assert cb2.http_url == f"http://{cb2.token}.oast.example.net/"
    assert s.get(cb2.token) is cb2
    assert s.poll_target(cb2.token) == f"https://oast.example.net/poll?id={cb2.token}"


def test_parse_interactions():
    assert oastmod.parse_interactions('[{"a":1}]') == [{"a": 1}]
    assert oastmod.parse_interactions('{"interactions":[{"x":2}]}') == [{"x": 2}]
    assert oastmod.parse_interactions("not json") == []


@pytest.mark.asyncio
async def test_oast_tools_flow(local_server, fresh_context):
    base, _ = local_server
    for n in ("oast_configure", "oast_generate", "oast_poll", "oast_list"):
        assert n in {t.name for t in await srv.mcp.list_tools()}
    gen = await srv.oast_generate(label="unconfigured")
    assert "OAST-UNCONFIGURED" in gen["http_url"] and gen.get("note")
    # point the poll at the local mock endpoint
    await srv.oast_configure(interaction_domain="canary.test",
                             poll_url=f"{base}/oast-poll?token={{token}}")
    g = await srv.oast_generate(label="ssrf")
    assert g["canary_host"] == f"{g['token']}.canary.test"
    lst = await srv.oast_list()
    assert lst["count"] >= 2 and lst["configured"] is True
    poll = await srv.oast_poll(token=g["token"])
    assert poll["interaction_count"] == 1
    assert poll["interactions"][0]["token"] == g["token"]


@pytest.mark.asyncio
async def test_oast_poll_unconfigured_lists_canaries(fresh_context):
    await srv.oast_generate(label="x")
    res = await srv.oast_poll()
    assert "canaries" in res and res["canaries"]


@pytest.mark.asyncio
async def test_trace_redirects_in_scope_chain(local_server, fresh_context):
    base, _ = local_server
    res = await srv.trace_redirects(target=f"{base}/r1")
    # /r1 -> /r2 -> / (terminal 200), all same host / in scope
    assert res["hop_count"] == 3
    assert res["hops"][0]["status"] == 302 and res["hops"][-1]["status"] == 200
    assert "redirect-leaves-scope" not in res["flags"]


@pytest.mark.asyncio
async def test_trace_redirects_flags_offsite_and_scope_exit(local_server, fresh_context):
    base, _ = local_server
    res = await srv.trace_redirects(target=f"{base}/redirect-out")
    # 302 -> http://evil.example/pwned : offsite AND out of scope, not followed
    assert "offsite-redirect" in res["flags"]
    assert "redirect-leaves-scope" in res["flags"]
    assert res["hops"][0]["location_in_scope"] is False
