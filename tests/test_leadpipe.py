"""Lead → PoC pipeline: classification, routing, and the promote_lead tool."""

import pytest

from moonmcp import leadpipe as lp
from moonmcp import server as srv


# -- pure classification ----------------------------------------------------
def test_classify_routes_injection_logic_and_smuggling():
    assert lp.classify_lead("sqli")["route"] == "confirm_finding"
    assert lp.classify_lead("multistep_bola")["route"] == "observe"
    assert lp.classify_lead("value_tampering")["family"] == "financial"
    d = lp.classify_lead("desync")
    assert d["route"] == "strix" and d["needs_strix"] is True


def test_classify_unknown_kind_has_safe_default():
    r = lp.classify_lead("something_new")
    assert r["family"] == "general" and r["route"] == "observe" and r["needs_strix"] is False


def test_confirmation_plan_shape_and_strix_brief_constraints():
    plan = lp.confirmation_plan("step_skip", "https://shop.test/checkout", "reached confirm cold")
    assert plan["family"] == "workflow" and plan["next_step"]
    assert "order placed without payment" in plan["confirmed_when"]
    brief = plan["strix_brief"]
    # the Strix hand-off is safety-bounded
    assert "non-destructive" in brief and "stop at proof" in brief
    assert "reached confirm cold" in brief and "shop.test" in brief


# -- promote_lead tool (records to findings + memory) -----------------------
@pytest.mark.asyncio
async def test_promote_lead_records_and_plans(fresh_context):
    res = await srv.promote_lead("https://api.test/orders/100", "multistep_bola",
                                 detail="B read order 205", severity="high")
    assert res["family"] == "authorization" and res["route"] == "observe"
    assert res["recorded"]["finding_id"] and res["recorded"]["memory_id"]
    # the lead is now in the findings store
    from moonmcp.server import get_context
    ctx = get_context()
    titles = [f.title for f in ctx.findings.list()]
    assert any("multistep_bola" in t for t in titles)


@pytest.mark.asyncio
async def test_promote_lead_can_skip_recording(fresh_context):
    res = await srv.promote_lead("acme.test", "sqli", record=False)
    assert "recorded" not in res and res["route"] == "confirm_finding"


@pytest.mark.asyncio
async def test_promote_lead_registered_and_offline():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "promote_lead" in tools
