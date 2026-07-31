"""Tests for hidden-parameter discovery."""

import pytest

from moonmcp import server as srv


@pytest.mark.asyncio
async def test_discover_parameters_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "discover_parameters" in tools


@pytest.mark.asyncio
async def test_discover_parameters_finds_reflected_and_behavioural(local_server, fresh_context):
    base, _ = local_server
    res = await srv.discover_parameters(target=f"{base}/reflect",
                                        wordlist=["name", "admin", "page", "q"])
    assert res["tested"] == 4
    found = {f["param"]: f["signal"] for f in res["found"]}
    # ?name= is echoed → reflected; ?admin= grows the body → length-change
    assert found.get("name") == "reflected"
    assert found.get("admin") in ("length-change", "status-change")
    # a param the app ignores must NOT be flagged
    assert "page" not in found


@pytest.mark.asyncio
async def test_discover_parameters_baseline_clean(local_server, fresh_context):
    base, _ = local_server
    # against a static page, an ignored wordlist should yield no findings
    res = await srv.discover_parameters(target=base, wordlist=["nonexistent_param_zzz"])
    assert res["found_count"] == 0


@pytest.mark.asyncio
async def test_discover_parameters_no_fp_on_query_echoing_page(local_server, fresh_context):
    # A page that reflects the WHOLE query string (canonical link) makes the canary
    # appear for every param — the junk-param control must suppress the reflection
    # signal so it isn't reported as N injection entry points.
    base, _ = local_server
    res = await srv.discover_parameters(target=f"{base}/echo-query",
                                        wordlist=["id", "user", "q", "page", "debug"])
    assert not any(f["signal"] == "reflected" for f in res["found"]), res
    # length is stable across params too (all echo the same-length canary) → no FP
    assert res["found_count"] == 0, res
