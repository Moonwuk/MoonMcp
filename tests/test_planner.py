"""plan_target — next-action ranking from the knowledge graph + findings."""

import pytest

from moonmcp import planner
from moonmcp import server as srv


def _tools(res):
    return [s["tool"] for s in res["suggestions"]]


# -- pure --------------------------------------------------------------------
def test_empty_target_recommends_baseline_recon():
    res = planner.plan([], [], target="new.example")
    tools = _tools(res)
    assert "recon_target" in tools
    assert "fingerprint" in tools
    assert res["finding_count"] == 0
    assert "nothing in memory" in res["note"]


def test_tech_signals_map_to_class_probes():
    ents = [
        {"kind": "technology", "name": "GraphQL (Apollo Server)"},
        {"kind": "technology", "name": "JWT"},
        {"kind": "service", "name": "AWS CloudFront"},
    ]
    tools = _tools(planner.plan(ents, [], target="t"))
    assert "graphql_probe" in tools
    assert "jwt_alg_confusion" in tools
    assert "ssrf_metadata_probe" in tools


def test_param_surface_triggers_injection_battery():
    ents = [{"kind": "param", "name": "id"}, {"kind": "endpoint", "name": "/api/x"},
            {"kind": "technology", "name": "nginx"}]
    tools = _tools(planner.plan(ents, [], target="t"))
    for probe in ("interp_probe", "sqli_probe", "cmdi_probe", "authz_probe"):
        assert probe in tools, probe


def test_existing_finding_demotes_that_class():
    ents = [{"kind": "param", "name": "id"}, {"kind": "technology", "name": "nginx"}]
    findings = [{"type": "sqli", "title": "SQLi on /search", "detail": "confirmed"}]
    res = planner.plan(ents, findings, target="t")
    sqli = next(s for s in res["suggestions"] if s["tool"] == "sqli_probe")
    assert sqli["already_evidence"] is True
    # …and it sorts below a not-yet-covered same-priority probe.
    order = _tools(res)
    assert order.index("cmdi_probe") < order.index("sqli_probe")


def test_priority_orders_high_impact_first():
    ents = [{"kind": "technology", "name": "JWT"}, {"kind": "param", "name": "q"}]
    res = planner.plan(ents, [], target="t")
    # the first non-already suggestion should be a P3 (high-impact) tool
    first = res["suggestions"][0]
    assert first["priority"] == 3


def test_signals_and_why_are_populated():
    ents = [{"kind": "technology", "name": "GraphQL"}]
    res = planner.plan(ents, [], target="t")
    g = next(s for s in res["suggestions"] if s["tool"] == "graphql_probe")
    assert g["why"]
    assert g["signals"]


# -- end-to-end --------------------------------------------------------------
@pytest.mark.asyncio
async def test_plan_target_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "plan_target" in tools


@pytest.mark.asyncio
async def test_plan_target_empty_memory(fresh_context):
    res = await srv.plan_target(target="unknown.example")
    assert res["target"] == "unknown.example"
    assert "recon_target" in [s["tool"] for s in res["suggestions"]]


@pytest.mark.asyncio
async def test_planner_only_emits_real_tools(fresh_context):
    live = {t.name for t in await srv.mcp.list_tools()}
    referenced = set()
    for _n, tools, _w in planner._TECH_SIGNALS:
        referenced |= set(tools)
    for t, _ in planner._INJECTION_BATTERY:
        referenced.add(t)
    for t, _ in planner._BASELINE:
        referenced.add(t)
    referenced |= set(planner._TOOL_CLASS)
    missing = referenced - live
    assert missing == set(), f"planner references non-existent tools: {missing}"


@pytest.mark.asyncio
async def test_plan_target_uses_recorded_entities(fresh_context):
    ctx = srv.get_context()
    ctx.memory.add_entity(kind="technology", name="GraphQL", target="shop.example")
    ctx.memory.add_entity(kind="param", name="id", target="shop.example")
    res = await srv.plan_target(target="shop.example")
    tools = [s["tool"] for s in res["suggestions"]]
    assert "graphql_probe" in tools
    assert "sqli_probe" in tools  # from the param surface battery
