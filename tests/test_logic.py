"""Business-logic abuse probes: parameter tampering, mass assignment, race."""

import pytest

from moonmcp import prompts as pmod
from moonmcp import server as srv
from moonmcp.web import logic


# -- pure helpers ------------------------------------------------------------
def test_numeric_params_and_query_keys():
    keys = logic.query_keys("https://x.test/buy?qty=1&color=red&amount=5")
    assert keys == ["qty", "color", "amount"]
    assert set(logic.numeric_params(keys)) == {"qty", "amount"}


def test_assess_tamper_accept_vs_reject():
    assert logic.assess_tamper(200, 500, 200, 500) is True     # accepted like baseline
    assert logic.assess_tamper(200, 500, 400, 20) is False     # rejected (4xx)
    assert logic.assess_tamper(200, 500, 200, 9000) is False   # different body
    assert logic.assess_tamper(None, 0, 200, 100) is False     # no baseline


# -- probes via fake clients -------------------------------------------------
class _R:
    def __init__(self, status, body=""):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body

    def text(self, limit=None):
        return self.body.decode()


class _SeqClient:
    """Returns responses in call order (first = baseline)."""

    def __init__(self, responses):
        self._responses = list(responses)
        self._i = 0

    async def fetch(self, url, **kwargs):
        r = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        return r


class _Client:
    def __init__(self, handler):
        self._handler = handler

    async def fetch(self, url, *, method="GET", body=None, headers=None, **kwargs):
        return self._handler(url, method, body)


@pytest.mark.asyncio
async def test_parameter_tampering_flags_accepted_invalid_values():
    # baseline 200/500 and every tampered value also 200/500 → all flagged
    client = _SeqClient([_R(200, "x" * 500)] * 20)
    res = await logic.probe_parameter_tampering(client, "https://x.test/buy?qty=1", "qty")
    assert res and all(f["verdict"] == "review" and f["kind"] == "parameter_tampering" for f in res)


@pytest.mark.asyncio
async def test_parameter_tampering_no_flag_when_rejected():
    # baseline 200, every tampered value 400 → nothing flagged
    client = _SeqClient([_R(200, "x" * 500)] + [_R(400, "bad")] * 12)
    res = await logic.probe_parameter_tampering(client, "https://x.test/buy?qty=1", "qty")
    assert res == []


@pytest.mark.asyncio
async def test_mass_assignment_flags_reflected_privileged_field():
    def handler(url, method, body):
        return _R(200, '{"user":{"role":"admin"},"ok":true}')
    res = await logic.probe_mass_assignment(_Client(handler), "https://x.test/api/users")
    assert any(f["field"] == "role" and f["severity"] == "high" for f in res)


@pytest.mark.asyncio
async def test_race_probe_flags_multiple_successes():
    res = await logic.probe_race(_Client(lambda u, m, b: _R(200)), "https://x.test/coupon", n=6)
    assert res["success_2xx"] == 6 and res["verdict"] == "review"

    res2 = await logic.probe_race(_Client(lambda u, m, b: _R(429)), "https://x.test/coupon", n=6)
    assert res2["success_2xx"] == 0 and res2["verdict"] == "no_race_signal"


# -- registration + prompt ---------------------------------------------------
@pytest.mark.asyncio
async def test_logic_tools_and_prompt_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert {"logic_probe", "race_probe"} <= tools
    prompts = {p.name for p in await srv.mcp.list_prompts()}
    assert "business_logic_hunt" in prompts


def test_business_logic_prompt_covers_the_categories():
    text = pmod.business_logic_hunt("acme.test", flow="checkout").lower()
    assert len(text) > 300
    for kw in ("parameter tampering", "mass assignment", "race", "idor", "workflow"):
        assert kw in text
