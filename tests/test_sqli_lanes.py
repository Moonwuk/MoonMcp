"""sqli_probe sharpenings (Theme C) — pure analysers + per-lane eval."""

import pytest

from moonmcp import server as srv
from moonmcp.web import probes as probesmod


# -- pure --------------------------------------------------------------------
def test_context_twins():
    assert probesmod.sqli_context_twins("value") == (probesmod.SQLI_TRUE, probesmod.SQLI_FALSE)
    ob_t, ob_f = probesmod.sqli_context_twins("order_by")
    assert "WHEN 1=1" in ob_t and "WHEN 1=2" in ob_f
    # unknown context falls back to value
    assert probesmod.sqli_context_twins("weird") == (probesmod.SQLI_TRUE, probesmod.SQLI_FALSE)


def test_oob_and_time_payloads():
    oob = dict(probesmod.sqli_oob_payloads("cnry.oast.test", "http://cnry.oast.test/t"))
    assert "http://cnry.oast.test/t" in oob["Oracle UTL_HTTP"]
    assert "cnry.oast.test" in oob["MSSQL xp_dirtree"]
    tp = dict(probesmod.sqli_time_payloads(5))
    assert "SLEEP(5)" in tp["MySQL"] and "0:0:5" in tp["MSSQL"]


def test_assess_timing():
    assert probesmod.assess_timing(0.02, 5.1, 5.0)["delta_s"] == pytest.approx(5.08, abs=0.01)
    assert probesmod.assess_timing(0.02, 0.4, 5.0) is None      # not slow enough
    assert probesmod.assess_timing(4.9, 5.2, 5.0) is None       # uniformly slow (delta too small)
    assert probesmod.assess_timing(0.0, 9.0, 0) is None         # no delay requested
    # A genuine SLEEP(5) is no longer discarded just because the backend's own
    # baseline (control) is above the requested delay — control subtraction, not an
    # absolute floor, is what rejects a uniformly-slow endpoint.
    assert probesmod.assess_timing(5.5, 10.5, 5.0)["delta_s"] == pytest.approx(5.0, abs=0.01)


def test_assess_timing_samples_confirms_scaling_delay():
    # real injection: delta scales with the requested sleep (1.0s -> ~1.0, 0.5s -> ~0.5)
    hit = probesmod.assess_timing_samples(
        control=[0.02, 0.03, 0.02], delayed=[1.01, 0.99], requested=1.0,
        confirm=[0.51, 0.49], requested_confirm=0.5)
    assert hit and hit["delta_s"] == pytest.approx(0.98, abs=0.05)
    assert hit["scaled"] >= 1.5


def test_assess_timing_samples_rejects_uniformly_slow_no_scaling():
    # a uniformly-slow endpoint: every request ~2s regardless of sleep value.
    # control subtraction already yields ~0 delta -> rejected.
    assert probesmod.assess_timing_samples(
        control=[2.0, 2.1, 1.95], delayed=[2.05, 2.0], requested=1.0,
        confirm=[2.02, 1.98], requested_confirm=0.5) is None


def test_assess_timing_samples_rejects_constant_offset_that_beats_threshold():
    # a target that always adds a big constant delay to THIS param (not sleep-scaled):
    # delayed and confirm both ~1.2s over control -> no scaling -> rejected.
    assert probesmod.assess_timing_samples(
        control=[0.02, 0.03, 0.02], delayed=[1.2, 1.25], requested=1.0,
        confirm=[1.2, 1.18], requested_confirm=0.5) is None


def test_assess_timing_samples_rejects_jitter_within_control_spread():
    # control itself is very noisy (0.1..1.5s); a delayed median 0.75s over it is not
    # separable from that jitter floor -> rejected before the scaling check.
    assert probesmod.assess_timing_samples(
        control=[0.1, 1.5, 0.2], delayed=[1.0, 0.9], requested=1.0,
        confirm=[0.6, 0.5], requested_confirm=0.5) is None


# -- per-lane end-to-end -----------------------------------------------------
@pytest.mark.asyncio
async def test_sqli_default_unchanged(local_server, fresh_context):
    base, _ = local_server
    res = await srv.sqli_probe(target=f"{base}/sqli", param="q")
    assert res["boolean_differential"] is True
    assert any(h["class"] == "sqli" for h in res["error_signatures"])
    assert "lanes" not in res and res["context"] == "value"


@pytest.mark.asyncio
async def test_sqli_order_by_context(local_server, fresh_context):
    base, _ = local_server
    res = await srv.sqli_probe(target=f"{base}/sqli-order", param="sort", context="order_by")
    assert res["context"] == "order_by" and res["boolean_differential"] is True


@pytest.mark.asyncio
async def test_sqli_multibyte_bypass(local_server, fresh_context):
    base, _ = local_server
    res = await srv.sqli_probe(target=f"{base}/sqli-mb", param="q", multibyte=True)
    lane = res["lanes"]["multibyte"]
    assert lane["plain_errored"] is False
    assert {h["charset"] for h in lane["bypass_charsets"]} >= {"GBK", "Shift-JIS", "EUC-KR"}


@pytest.mark.asyncio
async def test_sqli_waf_bypass(local_server, fresh_context):
    base, _ = local_server
    res = await srv.sqli_probe(target=f"{base}/sqli-waf", param="q", waf_bypass=True)
    lane = res["lanes"]["waf_bypass"]
    assert lane["plain_differential"] is False and lane["bypass"] is True
    assert any(e["encoding"] == "pgsql-jsonb" for e in lane["encoded_differentials"])


@pytest.mark.asyncio
async def test_sqli_time_based(local_server, fresh_context):
    base, _ = local_server
    res = await srv.sqli_probe(target=f"{base}/sqli-time", param="q", time_based=True, delay_s=1.0)
    hits = res["lanes"]["time_based"]["hits"]
    assert hits and any(h["delta_s"] >= 0.6 for h in hits)


@pytest.mark.asyncio
async def test_sqli_header_placement(local_server, fresh_context):
    base, _ = local_server
    res = await srv.sqli_probe(target=f"{base}/sqli-hdr", param="q",
                               placement="header", name="User-Agent")
    assert res["placement"] == "header"
    assert any(h["class"] == "sqli" for h in res["error_signatures"])
    assert res["boolean_differential"] is True


@pytest.mark.asyncio
async def test_sqli_oob_via_selfhost(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.sqli_probe(target=f"{base}/sqli-oob", param="q", oob=True, wait=1.5)
        assert res["lanes"]["oob"]["interaction_count"] >= 1, res
        assert res["verdict"] == "confirmed"
    finally:
        await srv.oast_selfhost(action="stop")
