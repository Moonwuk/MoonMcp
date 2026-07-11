"""Workflow / step-skipping abuse."""

import pytest

from moonmcp import server as srv
from moonmcp.web import workflow as wf


# -- pure helpers -----------------------------------------------------------
def test_normalize_steps_coerces_strings_and_dicts():
    steps = wf.normalize_steps(["https://x.test/cart", {"url": "https://x.test/pay", "method": "post"}])
    assert steps[0]["name"] == "step1" and steps[0]["method"] == "GET"
    assert steps[1]["method"] == "POST"
    assert wf.normalize_steps([{"no_url": 1}, ""]) == []   # invalid dropped


def test_assess_step_skip_rules():
    assert wf.assess_step_skip(200, "Order confirmed") is True          # 2xx, no enforcement
    assert wf.assess_step_skip(302, "") is False                        # redirect = enforced
    assert wf.assess_step_skip(403, "nope") is False                    # blocked
    assert wf.assess_step_skip(200, "Please complete the previous step") is False  # enforcement text
    assert wf.assess_step_skip(200, "welcome", success_marker="order confirmed") is False  # marker absent
    assert wf.assess_step_skip(200, "ORDER CONFIRMED #12", success_marker="order confirmed") is True


# -- probe via fake apps ----------------------------------------------------
class _R:
    def __init__(self, status, body):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body

    def text(self, limit=None):
        return self.body.decode()


class _BrokenFlow:
    """Serves every step cold — no sequence enforcement."""

    async def fetch(self, url, **kwargs):
        if url.endswith("/confirm"):
            return _R(200, "Order confirmed #A1 — thank you")
        return _R(200, "step page content here")


class _EnforcedFlow:
    """Every later step redirects back to the start."""

    async def fetch(self, url, **kwargs):
        return _R(302, "")


FLOW = [
    {"url": "https://x.test/cart", "name": "cart"},
    {"url": "https://x.test/payment", "name": "payment"},
    {"url": "https://x.test/confirm", "name": "confirm", "success": "order confirmed"},
]


@pytest.mark.asyncio
async def test_broken_flow_flags_step_skip_with_terminal_high():
    res = await wf.probe_workflow_skip(_BrokenFlow(), FLOW)
    names = {f["step"] for f in res["findings"]}
    assert {"payment", "confirm"} <= names       # both later steps served cold
    confirm = next(f for f in res["findings"] if f["step"] == "confirm")
    assert confirm["terminal"] is True and confirm["severity"] == "high"
    assert res["verdict"] == "review"


@pytest.mark.asyncio
async def test_enforced_flow_no_findings():
    res = await wf.probe_workflow_skip(_EnforcedFlow(), FLOW)
    assert res["findings"] == [] and res["verdict"] == "no_step_skip"


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_workflow_probe_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "workflow_probe" in tools
