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


_LITE_SAMPLE = """
<table>
<tr><td><a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa"
   class='result-link'>Alpha Result</a></td></tr>
<tr><td class='result-snippet'>Snippet for alpha.</td></tr>
<tr><td><a href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fb"
   class='result-link'>Beta Result</a></td></tr>
<tr><td class='result-snippet'>Snippet for beta.</td></tr>
</table>
"""

_BING_SAMPLE = """
<ol id="b_results">
<li class="b_algo"><h2><a href="https://example.com/one">First &amp; Best</a></h2>
  <div><p class="b_lineclamp2">Bing snippet one.</p></div></li>
<li class="b_algo"><h2><a href="https://example.com/two">Second</a></h2>
  <p>Bing snippet two.</p></li>
</ol>
"""


def test_parse_ddg_html():
    results = searchmod.parse_ddg_html(_DDG_SAMPLE)
    assert len(results) == 2
    assert results[0]["title"] == "Example Admin"        # tags stripped
    assert results[0]["url"] == "https://example.com/admin"  # uddg decoded
    assert "admin panel" in results[0]["snippet"].lower()
    assert results[1]["url"] == "https://docs.example.com/"


def test_parse_ddg_lite():
    results = searchmod.parse_ddg_lite(_LITE_SAMPLE)
    assert len(results) == 2
    assert results[0]["title"] == "Alpha Result"
    assert results[0]["url"] == "https://example.com/a"      # uddg decoded
    assert "alpha" in results[0]["snippet"].lower()


def test_parse_bing():
    results = searchmod.parse_bing(_BING_SAMPLE)
    assert len(results) == 2
    assert results[0]["title"] == "First & Best"            # entity-decoded
    assert results[0]["url"] == "https://example.com/one"   # direct href
    assert "snippet one" in results[0]["snippet"].lower()
    assert results[1]["url"] == "https://example.com/two"


def test_dedup_drops_repeat_urls():
    deduped = searchmod._dedup([
        {"url": "https://example.com/x", "title": "a"},
        {"url": "https://example.com/x/", "title": "b"},   # trailing slash = same
        {"url": "https://example.com/y", "title": "c"},
    ])
    assert [d["title"] for d in deduped] == ["a", "c"]


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
    # Network-agnostic: if no engine returned results (e.g. blocked sandbox), it must
    # have tried them all before giving up. If the network is up and an engine answered
    # (as on CI runners), `engines_tried` is absent — that's success, not a failure.
    if not res["results"]:
        assert set(res.get("engines_tried", [])) >= {"duckduckgo", "bing"}


@pytest.mark.asyncio
async def test_web_search_site_filter_scopes_query(fresh_context):
    # The site= filter prepends site:<domain>; the reflected query proves it even
    # when the network is blocked and no results come back.
    res = await srv.web_search(query="admin panel", site="example.com")
    assert res["query"].startswith("site:example.com ")
    # already-present site: isn't doubled
    res2 = await srv.web_search(query="site:example.com login", site="example.com")
    assert res2["query"].count("site:example.com") == 1
