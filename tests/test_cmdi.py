"""cmdi_probe — blind OS command injection (timing + OAST), pure analysers + e2e."""

import pytest

from moonmcp import server as srv
from moonmcp.web import probes as probesmod


# -- pure ---------------------------------------------------------------------
def test_cmdi_time_payloads_cover_separators_and_never_leak_output():
    payloads = dict(probesmod.cmdi_time_payloads(3))
    assert payloads["semicolon"] == "1;sleep 3"
    assert payloads["pipe"] == "1|sleep 3"
    assert payloads["and"] == "1&&sleep 3"
    assert payloads["background"] == "1&sleep 3"
    assert payloads["backtick"] == "1`sleep 3`"
    assert payloads["dollar-paren"] == "1$(sleep 3)"
    # never a payload designed to elicit readable output
    joined = " ".join(payloads.values()).lower()
    assert "id" not in joined.split() and "passwd" not in joined and "dir" not in joined.split()


def test_cmdi_oob_payloads_carry_no_output():
    payloads = dict(probesmod.cmdi_oob_payloads("http://canary.oast.test/x"))
    assert payloads["semicolon"] == "1;curl http://canary.oast.test/x"
    assert all("curl http://canary.oast.test/x" in v for v in payloads.values())
    # the callback URL is the sole argument to curl — nothing follows it except the
    # separator's own closing wrapper (backtick / closing paren), never extra data.
    for label, v in payloads.items():
        after = v.split("http://canary.oast.test/x", 1)[1]
        assert after in ("", "`", ")"), (label, after)


# -- end-to-end -----------------------------------------------------------------
@pytest.mark.asyncio
async def test_cmdi_probe_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "cmdi_probe" in tools


@pytest.mark.asyncio
async def test_cmdi_time_based_detects_vulnerable_endpoint(local_server, fresh_context):
    base, _ = local_server
    res = await srv.cmdi_probe(target=f"{base}/cmdi-time", param="q", delay_s=1.0)
    hits = res["lanes"]["time_based"]["hits"]
    assert hits and any(h["delta_s"] >= 0.6 for h in hits)
    assert res["verdict"] in ("likely", "confirmed")


@pytest.mark.asyncio
async def test_cmdi_time_based_no_hit_on_safe_endpoint(local_server, fresh_context):
    base, _ = local_server
    res = await srv.cmdi_probe(target=f"{base}/cmdi-safe", param="q", delay_s=1.0)
    assert res["lanes"]["time_based"]["hits"] == []
    assert res["verdict"] == "unconfirmed"


@pytest.mark.asyncio
async def test_cmdi_oob_via_selfhost(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.cmdi_probe(target=f"{base}/cmdi-oob", param="q",
                                   time_based=False, oob=True, wait=1.5)
        assert res["lanes"]["oob"]["interaction_count"] >= 1, res
        assert res["verdict"] == "confirmed"
    finally:
        await srv.oast_selfhost(action="stop")


@pytest.mark.asyncio
async def test_cmdi_oob_unconfigured_reports_error(fresh_context, local_server):
    base, _ = local_server
    res = await srv.cmdi_probe(target=f"{base}/cmdi-safe", param="q",
                               time_based=False, oob=True)
    assert res["lanes"]["oob"]["error"] == "oast_unconfigured"
    assert res["verdict"] == "unconfirmed"
