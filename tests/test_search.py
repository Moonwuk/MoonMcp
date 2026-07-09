"""Tests for the internet-search tools (web_search + search_dorks)."""

import pytest

from moonmcp import server as srv
from moonmcp.intel import search as searchmod

# A trimmed sample of DuckDuckGo's HTML result markup.
_DDG_SAMPLE = """
<div class="result results_links">
  <a rel="nofollow" class="result__a"
     href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fadmin&amp;rut=abc">Example <b>Admin</b></a>
  <a class="result__snippet" href="x">The admin panel for Example &amp; co.</a>
</div>
<div class="result results_links">
  <a rel="nofollow" class="result__a"
     href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdocs.example.com%2F">Example Docs</a>
  <a class="result__snippet" href="y">Developer documentation.</a>
</div>
"""


def test_parse_ddg_html():
    results = searchmod.parse_ddg_html(_DDG_SAMPLE)
    assert len(results) == 2
    assert results[0]["title"] == "Example Admin"        # tags stripped
    assert results[0]["url"] == "https://example.com/admin"  # uddg decoded
    assert "admin panel" in results[0]["snippet"].lower()
    assert results[1]["url"] == "https://docs.example.com/"


def test_generate_dorks_all_and_category():
    alld = searchmod.generate_dorks("example.com")
    assert alld["count"] > 0
    assert "config_secrets" in alld["categories"]
    assert all("example.com" in q for qs in alld["dorks"].values() for q in qs)
    one = searchmod.generate_dorks("example.com", category="login_admin")
    assert one["category"] == "login_admin" and one["dorks"]
    bad = searchmod.generate_dorks("example.com", category="nope")
    assert "error" in bad


@pytest.mark.asyncio
async def test_search_tools_registered_and_dorks(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "web_search" in tools and "search_dorks" in tools
    d = await srv.search_dorks(domain="example.com", category="files")
    assert d["dorks"] and "ext:sql" in " ".join(d["dorks"])


@pytest.mark.asyncio
async def test_web_search_handles_blocked_network(fresh_context):
    # No outbound network in the test sandbox → the tool must degrade gracefully,
    # not raise, returning an empty result set with an error note.
    res = await srv.web_search(query="site:example.com admin")
    assert res["query"] == "site:example.com admin"
    assert isinstance(res.get("results"), list)
