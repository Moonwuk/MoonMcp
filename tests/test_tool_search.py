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
    res = toolsearch.search("idor orders", phase="auth", available_only=False, limit=5)
    names = [c["name"] for c in res["candidates"]]
    assert any(n in names for n in ("access_control_check", "authz_probe")), names

    res2 = toolsearch.search("blind ssrf callback", phase="ssrf", available_only=False, limit=5)
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


def test_labelled_retrieval_regressions():
    """Reviewed development cases, not an independent multilingual benchmark."""
    cases = [
        ("scope", "scope_list", {"scope_add", "scope_remove"}),
        ("check scope", "scope_list", {"scope_add", "scope_exclude"}),
        ("add scope", "scope_add", {"scope_remove"}),
        ("run budget", "run_status", {"agent_tree", "program_add"}),
        ("sql injection", "sqli_probe", {"oast_generate", "waf_efficacy"}),
        ("sqli", "sqli_probe", {"oast_generate", "waf_efficacy"}),
        ("browser screenshot", "screenshot", {"jwt_analyze"}),
        ("проверить авторизацию", "access_control_check", {"auth_clear", "auth_set"}),
        ("身份验证", "access_control_check", {"auth_clear", "auth_set"}),
        ("인증 검사", "access_control_check", {"auth_clear", "auth_set"}),
        ("verificar autorização", "access_control_check", {"auth_clear", "auth_set"}),
        ("प्राधिकरण जांच", "access_control_check", {"auth_clear", "auth_set"}),
    ]
    for query, expected, negatives in cases:
        names = [c["name"] for c in toolsearch.search(query, available_only=False)["candidates"]]
        assert names[0] == expected, (query, names)
        assert names[0] not in negatives


def test_exact_identifier_and_unicode_components():
    assert {"sqli", "probe", "sqli_probe"} <= toolsearch._tokens("sqli_probe")
    assert "प्राधिकरण" in toolsearch._tokens("प्राधिकरण जांच")
    for query in ("sqli_probe", "ＳＱＬＩ＿ＰＲＯＢＥ"):
        assert toolsearch.search(query, available_only=False)["candidates"][0]["name"] == "sqli_probe"
    assert toolsearch.search("qzxvbn")['candidates'] == []
    assert "sqli" not in toolsearch._query_tokens("nosql injection")
    assert "sqli" not in toolsearch._query_tokens("sql injectional")


def test_availability_and_live_registry_changes(monkeypatch):
    from moonmcp import toolspec

    snapshot = toolspec.capabilities()
    snapshot["browser"] = {"status": "unavailable", "reason": "playwright_package_missing"}
    monkeypatch.setattr(toolspec, "capabilities", lambda settings=None: snapshot)
    visible = toolsearch.search("screenshot", available_only=False)["candidates"]
    assert visible[0]["name"] == "screenshot"
    assert visible[0]["availability"]["status"] == "unavailable"
    assert all(c["name"] != "screenshot" for c in toolsearch.search("screenshot")["candidates"])

    manager = srv.mcp._tool_manager
    exposed = [tool for tool in manager.list_tools() if tool.name in cat._ALWAYS_ON]
    monkeypatch.setattr(manager, "list_tools", lambda: exposed)
    assert toolsearch.search("sqli", available_only=False)["candidates"] == []
    assert toolspec.describe("sqli_probe")["error"] == "tool_unavailable"
