"""Value / financial-logic manipulation."""

import pytest

from moonmcp import server as srv
from moonmcp.web import value as v


# -- field detection --------------------------------------------------------
def test_field_classifiers():
    keys = ["amount", "currency", "coupon", "color", "wallet_balance", "ccy"]
    assert set(v.money_fields(keys)) >= {"amount", "coupon", "wallet_balance"}
    assert set(v.currency_fields(keys)) == {"currency", "ccy"}
    assert "coupon" in v.coupon_fields(keys)
    assert "color" not in v.money_fields(keys)


# -- fake clients -----------------------------------------------------------
class _R:
    def __init__(self, status, body=b""):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body


class _Seq:
    """Baseline (first call) then a fixed response for the rest."""

    def __init__(self, baseline, rest):
        self._baseline = baseline
        self._rest = rest
        self._i = 0

    async def fetch(self, url, **kwargs):
        self._i += 1
        return self._baseline if self._i == 1 else self._rest


class _SeqList:
    """Responses in call order (last repeats)."""

    def __init__(self, responses):
        self._r = list(responses)
        self._i = 0

    async def fetch(self, url, **kwargs):
        r = self._r[min(self._i, len(self._r) - 1)]
        self._i += 1
        return r


@pytest.mark.asyncio
async def test_value_tampering_flags_accepted_categories():
    # baseline, garbage CONTROL rejected (400), then every manipulation accepted (200/500)
    client = _SeqList([_R(200, "x" * 500), _R(400, "bad")] + [_R(200, "x" * 500)] * 30)
    res = await v.probe_value_tampering(client, "https://x.test/pay?amount=1", "amount")
    cats = {f["category"] for f in res}
    assert {"negative", "zero", "overflow", "precision", "over_100_percent"} <= cats
    assert any(f["severity"] == "high" for f in res)   # negative / >100% are high


@pytest.mark.asyncio
async def test_value_tampering_no_flag_when_rejected():
    client = _Seq(_R(200, "x" * 500), _R(400, "bad"))
    res = await v.probe_value_tampering(client, "https://x.test/pay?amount=1", "amount")
    assert res == []


@pytest.mark.asyncio
async def test_value_tampering_suppressed_when_field_not_validated():
    # baseline AND garbage control both accepted-like-baseline → field ignores input → no FPs
    client = _Seq(_R(200, "x" * 500), _R(200, "x" * 500))
    res = await v.probe_value_tampering(client, "https://x.test/pay?amount=1", "amount")
    assert res == []


@pytest.mark.asyncio
async def test_currency_swap_flags_accepted():
    client = _Seq(_R(200, "x" * 300), _R(200, "x" * 300))
    res = await v.probe_currency_swap(client, "https://x.test/pay?currency=USD", "currency")
    assert res and all(f["kind"] == "currency_swap" for f in res)


@pytest.mark.asyncio
async def test_coupon_reuse_verdict():
    ok = await v.probe_coupon_reuse(_Seq(_R(200), _R(200)), "https://x.test/apply", "coupon", "SAVE", times=3)
    assert ok["successes"] == 3 and ok["verdict"] == "review"

    class _OnceThen409:
        def __init__(self):
            self._i = 0

        async def fetch(self, url, **kwargs):
            self._i += 1
            return _R(200) if self._i == 1 else _R(409)

    no = await v.probe_coupon_reuse(_OnceThen409(), "https://x.test/apply", "coupon", "SAVE", times=3)
    assert no["successes"] == 1 and no["verdict"] == "no_reuse_signal"


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_value_lanes_folded_into_logic_probe():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "value_probe" not in tools     # value/currency/coupon lanes folded into logic_probe
    assert "logic_probe" in tools
    tool = next(t for t in srv.mcp._tool_manager.list_tools() if t.name == "logic_probe")
    assert "coupon_code" in tool.parameters.get("properties", {})
