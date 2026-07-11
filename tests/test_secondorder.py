"""Second-order (stored) SQLi — pure analysers + stateful write→read eval."""

import pytest

from moonmcp import server as srv
from moonmcp.web import secondorder as so


def _mysql_sig(text):
    return [{"matched": "sql syntax", "technology": "MySQL"}] if "syntax" in (text or "").lower() else []


# -- pure --------------------------------------------------------------------
def test_seed_payloads_equal_length_boolean():
    tag = "moon2oABCD1234"
    s = so.seed_payloads(tag)
    assert all(v.startswith(tag) for v in s.values())
    assert len(s["true"]) == len(s["false"])          # a verbatim echo yields no diff


def test_make_tag_prefix():
    t = so.make_tag()
    assert t.startswith(so.TAG_PREFIX) and len(t) > len(so.TAG_PREFIX)


def test_normalize_reads():
    assert so.normalize_reads("http://x/a") == [{"url": "http://x/a", "method": "GET"}]
    got = so.normalize_reads(["http://x/a", {"url": "http://x/b", "method": "post"}])
    assert got == [{"url": "http://x/a", "method": "GET"}, {"url": "http://x/b", "method": "POST"}]


def _obs(status, text):
    return so.ReadObs(status, text)


def test_assess_read_error_lane():
    tag = "moon2oXY"
    hit = so.assess_read(
        tag,
        control=_obs(200, f"comment: {tag}ctl"),
        error=_obs(200, f"MySQL syntax error near {tag}'"),
        true=_obs(200, f"{tag} rows: a b c"),
        false=_obs(200, f"{tag} rows:"),
        match_fn=_mysql_sig)
    assert hit and hit["severity"] == "high" and hit["error_signatures"]


def test_assess_read_boolean_lane_without_error():
    tag = "moon2oXY"
    hit = so.assess_read(
        tag,
        control=_obs(200, f"c {tag}ctl"),
        error=_obs(200, f"c {tag}'"),                 # echoed, no SQL error
        true=_obs(200, f"c {tag} rows: a b c d e"),
        false=_obs(200, f"c {tag} rows:"),
        match_fn=_mysql_sig)
    assert hit and hit["severity"] == "medium" and hit["boolean_differential"] is True


def test_assess_read_no_signal():
    tag = "moon2oXY"
    # tag never reflected, no error, identical reads → nothing
    assert so.assess_read(tag, _obs(200, "x"), _obs(200, "x"), _obs(200, "x"), _obs(200, "x"),
                          _mysql_sig) is None


# -- end-to-end against the stateful /store → /render flow -------------------
@pytest.mark.asyncio
async def test_second_order_detects(local_server, fresh_context):
    base, _ = local_server
    res = await srv.second_order_sqli_probe(
        write={"url": f"{base}/store", "method": "POST"}, read=[f"{base}/render"], param="comment")
    assert res["verdict"] in ("likely", "confirmed"), res
    assert res["findings"] and res["findings"][0]["error_signatures"]
    assert res["findings"][0]["reflected"] is True


@pytest.mark.asyncio
async def test_second_order_no_false_positive(local_server, fresh_context):
    base, _ = local_server
    # /reflect ignores the stored value entirely → tag never surfaces, no differential
    res = await srv.second_order_sqli_probe(
        write={"url": f"{base}/store", "method": "POST"}, read=[f"{base}/reflect"], param="comment")
    assert res["findings"] == [] and res["verdict"] == "unconfirmed"


@pytest.mark.asyncio
async def test_second_order_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.second_order_sqli_probe(
        write={"url": f"{base}/store"}, read=[f"{base}/render"])
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_second_order_oob_via_selfhost(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.second_order_sqli_probe(
            write={"url": f"{base}/store", "method": "POST"}, read=[f"{base}/render"],
            param="comment", oob=True, wait=1.5)
        assert res["oob"]["interaction_count"] >= 1, res
        assert res["verdict"] == "confirmed"
    finally:
        await srv.oast_selfhost(action="stop")


@pytest.mark.asyncio
async def test_second_order_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "second_order_sqli_probe" in tools
