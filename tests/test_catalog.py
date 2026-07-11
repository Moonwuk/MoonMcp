"""The tool_catalog must describe every registered tool exactly once, and its
gate flags must match the real @active_tool markers.
"""

import pytest

from moonmcp import catalog as cat
from moonmcp import server as srv


def _meta():
    return {
        t.name: {
            "description": t.description or "",
            "gated": getattr(t.fn, "__moonmcp_gated__", False),
            "intrusive": getattr(t.fn, "__moonmcp_intrusive__", False),
        }
        for t in srv.mcp._tool_manager.list_tools()
    }


def test_every_tool_is_categorized_exactly_once():
    registered = set(_meta())
    # No tool registered but missing from a family.
    result = cat.build_catalog(_meta())
    assert "uncategorized" not in result, result.get("uncategorized")
    # No family lists a tool that isn't registered.
    stale = sorted(set(cat.TOOL_FAMILY) - registered)
    assert not stale, f"catalog lists non-existent tools: {stale}"
    # Each tool appears in exactly one family (FAMILIES has no dupes).
    seen: dict[str, str] = {}
    dupes = []
    for fam, (_t, _b, names) in cat.FAMILIES.items():
        for n in names:
            if n in seen:
                dupes.append((n, seen[n], fam))
            seen[n] = fam
    assert not dupes, f"tools in multiple families: {dupes}"


def test_catalog_gate_flags_match_markers():
    meta = _meta()
    result = cat.build_catalog(meta)
    for fam in result["families"]:
        for tool in fam["tools"]:
            m = meta[tool["name"]]
            assert tool["scope_gated"] == bool(m["gated"]), tool["name"]
            assert tool["intrusive"] == bool(m["intrusive"]), tool["name"]


def test_catalog_family_filter():
    result = cat.build_catalog(_meta(), family="intrusive")
    assert len(result["families"]) == 1
    fam = result["families"][0]
    assert fam["family"] == "intrusive"
    assert {t["name"] for t in fam["tools"]} == {
        "port_scan", "content_discovery", "http_methods",
        "waf_efficacy", "desync_probe", "desync_modern_probe", "vuln_scan",
        "cache_deception_probe", "stack_probe", "ssrf_metadata_probe",
        "logic_probe", "race_probe", "workflow_probe", "value_probe", "jwt_jku_probe",
        "nosqli_probe", "db_exposure", "second_order_sqli_probe", "orm_leak_probe",
        "fastjson_oast_probe", "ssrf_protocol_probe", "parser_diff_probe",
        "graphql_nosqli",
    }
    assert all(t["intrusive"] for t in fam["tools"])


@pytest.mark.asyncio
async def test_tool_catalog_tool_runs():
    res = await srv.tool_catalog()
    assert res["total_tools"] >= 90
    assert res["workflow"]
    fams = {f["family"] for f in res["families"]}
    assert {"setup", "passive_osint", "light_active", "intrusive"} <= fams
    # server_status/tool_catalog live in setup and are NOT gated.
    setup = next(f for f in res["families"] if f["family"] == "setup")
    tc = next(t for t in setup["tools"] if t["name"] == "tool_catalog")
    assert tc["scope_gated"] is False
