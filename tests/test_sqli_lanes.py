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
    assert probesmod.assess_timing(4.9, 5.2, 5.0) is None       # uniformly slow (control already slow)
    assert probesmod.assess_timing(0.0, 9.0, 0) is None         # no delay requested


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
