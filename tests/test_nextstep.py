"""suggested_next — standardised next-tool hints on the detection probes."""

import pytest

from moonmcp import nextstep
from moonmcp import server as srv


# -- pure --------------------------------------------------------------------
def test_after_positive_verdict_returns_chain():
    assert nextstep.after("sqli_probe", "confirmed") == ["confirm_finding"]
    assert nextstep.after("ssrf_probe", "likely")[0] == "oast_poll"


def test_after_negative_verdict_is_empty():
    assert nextstep.after("sqli_probe", "unconfirmed") == []
    assert nextstep.after("ssti_probe", "inconclusive") == []
    assert nextstep.after("interp_none", "none") == []


def test_after_none_verdict_is_verdict_agnostic():
    # recon tools call it with no verdict — always suggest.
    assert nextstep.after("fingerprint") == ["plan_target"]
    assert "jwt_crack" in nextstep.after("jwt_analyze")


def test_after_unknown_tool_is_empty():
    assert nextstep.after("does_not_exist", "confirmed") == []


def test_after_returns_a_copy_not_the_shared_list():
    got = nextstep.after("jwt_analyze")
    got.append("mutated")
    assert "mutated" not in nextstep.AFTER["jwt_analyze"]


def test_referenced_tools_covers_keys_and_values():
    refs = nextstep.referenced_tools()
    assert "sqli_probe" in refs          # a key
    assert "confirm_finding" in refs     # a value
    assert "plan_target" in refs


# -- drift guard -------------------------------------------------------------
@pytest.mark.asyncio
async def test_every_referenced_tool_exists(fresh_context):
    live = {t.name for t in await srv.mcp.list_tools()}
    missing = nextstep.referenced_tools() - live
    assert missing == set(), f"nextstep points at non-existent tools: {missing}"


# -- e2e: probes actually carry the field ------------------------------------
@pytest.mark.asyncio
async def test_sqli_probe_result_carries_suggested_next(local_server, fresh_context):
    base, _ = local_server
    res = await srv.sqli_probe(target=f"{base}/sqli", param="id")
    assert "suggested_next" in res
    # on a positive verdict it points at confirm_finding; on a clean one it's [].
    if res.get("verdict") in ("confirmed", "likely"):
        assert res["suggested_next"] == ["confirm_finding"]
    else:
        assert res["suggested_next"] == []


@pytest.mark.asyncio
async def test_fingerprint_result_carries_suggested_next(local_server, fresh_context):
    base, _ = local_server
    res = await srv.fingerprint(target=base)
    assert res.get("suggested_next") == ["plan_target"]
