"""search_tools — progressive tool discovery: pure ranker + e2e."""

import pytest

from moonmcp import server as srv
from moonmcp import toolsearch

_ENTRIES = [
    {"name": "graphql_probe", "family": "intercept", "gist": "GraphQL batch/BOLA probe"},
    {"name": "graphql_check", "family": "light_active", "gist": "GraphQL introspection"},
    {"name": "sqli_probe", "family": "intercept", "gist": "SQL injection detector"},
    {"name": "cache_probe", "family": "intercept", "gist": "web cache poisoning"},
    {"name": "fingerprint", "family": "light_active", "gist": "identify the tech stack"},
]


def _names(res):
    return [r["name"] for r in res]


# -- pure --------------------------------------------------------------------
def test_name_match_outranks_family_and_gist():
    # "graphql" hits two tools in BOTH name (5) and gist (1) → 6 each; nothing else.
    res = toolsearch.rank("graphql", _ENTRIES)
    assert set(_names(res)) == {"graphql_probe", "graphql_check"}
    assert all(r["score"] == 6 for r in res)


def test_gist_only_match_still_returned_but_lower():
    res = toolsearch.rank("poisoning", _ENTRIES)  # only in cache_probe's gist
    assert _names(res) == ["cache_probe"]
    assert res[0]["score"] == 1


def test_family_match_scores_two():
    res = toolsearch.rank("intercept", _ENTRIES)
    assert res  # several intercept-family tools
    assert all(r["score"] == 2 for r in res)


def test_no_match_returns_empty():
    assert toolsearch.rank("nonexistentxyz", _ENTRIES) == []


def test_short_tokens_are_dropped():
    # single-char / 1-char tokens are noise and must not match everything.
    assert toolsearch.rank("a", _ENTRIES) == []


def test_limit_is_respected():
    res = toolsearch.rank("probe", _ENTRIES, limit=2)
    assert len(res) <= 2


def test_multi_token_scores_sum():
    # "cache poisoning" on cache_probe: 'cache' in name (5) + 'cache' in gist (1)
    # + 'poisoning' in gist (1) = 7.
    res = toolsearch.rank("cache poisoning", _ENTRIES)
    top = res[0]
    assert top["name"] == "cache_probe"
    assert top["score"] == 7


# -- e2e ---------------------------------------------------------------------
@pytest.mark.asyncio
async def test_search_tools_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "search_tools" in tools


@pytest.mark.asyncio
async def test_search_tools_graphql(fresh_context):
    res = await srv.search_tools(query="graphql", limit=5)
    names = [r["name"] for r in res["results"]]
    assert "graphql_check" in names
    assert "graphql_probe" in names
    assert res["count"] == len(res["results"])


@pytest.mark.asyncio
async def test_search_tools_jwt_returns_jwt_family(fresh_context):
    res = await srv.search_tools(query="jwt", limit=6)
    names = [r["name"] for r in res["results"]]
    assert any(n.startswith("jwt_") for n in names)
    assert all("jwt" in r["name"] or "jwt" in r["gist"].lower()
               for r in res["results"])
