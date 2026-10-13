"""tool_search contracts (AGENT_NAVIGATION_PLAN.md stage 1).

The search must (a) only ever return REAL registered tools, (b) give a
reason per candidate, (c) stay short (<=10), (d) be reachable even
under the fail-closed orientation-only profile — it IS an orientation
tool.
"""


from moonmcp import catalog as cat
from moonmcp import server as srv
from moonmcp import toolsearch


def _registered() -> set[str]:
    return {t.name for t in srv.mcp._tool_manager.list_tools()}


def test_candidates_are_real_tools_with_reasons():
    for query, phase in [("idor", "auth"), ("blind ssrf", "ssrf"), ("report", "report")]:
        res = toolsearch.search(query, phase=phase)
        assert 1 <= res["count"] <= 10
        for c in res["candidates"]:
            assert c["name"] in _registered(), f"unknown tool proposed: {c['name']}"
            assert c["reason"], "candidate without a reason"
            assert c["family"] in cat.FAMILIES or c["family"] == "uncategorized"
            # gate flags survive into the card
            assert isinstance(c["scope_gated"], bool)
            assert isinstance(c["intrusive"], bool)


def test_limit_is_respected():
    res = toolsearch.search("probe", limit=3)
    assert res["count"] <= 3


def test_relevance_top_hits():
    """The point of the tool: the right answer lands in the top few."""
    res = toolsearch.search("idor orders", phase="auth", limit=5)
    names = [c["name"] for c in res["candidates"]]
    assert any(n in names for n in ("access_control_check", "authz_probe")), names

    res2 = toolsearch.search("blind ssrf callback", phase="ssrf", limit=5)
    names2 = [c["name"] for c in res2["candidates"]]
    assert "ssrf_probe" in names2, names2


def test_registered_as_mcp_tool_and_always_on():
    assert "tool_search" in _registered()
    assert "tool_search" in cat._ALWAYS_ON
    # an orientation tool must survive an unknown (fail-closed) profile
    allowed = cat.select_profile(_registered(), profile="bogus-profile")
    assert "tool_search" in allowed


def test_passive_allowlist_has_tool_search():
    """No traffic — it reads the local registry only."""
    import tests.test_active_tool_guard as guard
    assert "tool_search" in guard.PASSIVE, (
        "tool_search sends no traffic — it belongs in PASSIVE")