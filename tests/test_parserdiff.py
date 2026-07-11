"""HTTP parser-differential probe — pure encoders/analysers + end-to-end eval."""

from urllib.parse import unquote_to_bytes

import pytest

from moonmcp import server as srv
from moonmcp.web import parserdiff as pd


# -- encoders ----------------------------------------------------------------
def test_utf7_shift_round_trips():
    # a server that decodes UTF-7 turns the shifted block back into the canary
    shifted = pd.utf7_shift(pd.CANARY)
    assert shifted.startswith("+") and shifted.endswith("-")
    assert pd.CANARY not in shifted                      # canary is NOT present literally
    assert shifted.encode("ascii").decode("utf-7") == pd.CANARY


def test_overlong_encodes_two_bytes_each():
    enc = pd.overlong("A")                                # 0x41 → 0xC1 0x81
    assert enc == "%C1%81"
    bs = unquote_to_bytes(pd.overlong(pd.CANARY))
    assert pd.CANARY.encode() not in bs                  # not present as plain ASCII
    # every char became a 2-byte C0/C1 overlong sequence
    assert len(bs) == 2 * len(pd.CANARY)
    assert all(bs[i] in (0xC0, 0xC1) for i in range(0, len(bs), 2))


def test_request_builders_shape():
    _, b, h = pd.json_dupkey("https://x/a", "p", pd.DECOY, pd.CANARY)
    assert b == f'{{"p":"{pd.DECOY}","p":"{pd.CANARY}"}}'.encode()
    assert h["Content-Type"] == "application/json"
    _, b, h = pd.utf7_form("https://x/a", "p", pd.CANARY)
    assert "charset=utf-7" in h["Content-Type"] and b"+" not in b   # + is percent-encoded
    u, b, h = pd.overlong_query("https://x/a?z=1", "p", pd.CANARY)
    assert u.startswith("https://x/a?z=1&p=%C") and b is None
    _, b, h = pd.multipart_dup("https://x/a", "p", pd.DECOY, pd.CANARY)
    assert b.count(b'name="p"') == 2 and "multipart/form-data" in h["Content-Type"]


def test_bom_and_lf_builders():
    _, b, h = pd.json_bom("https://x/a", "p", pd.CANARY)
    assert b.startswith(b"\xef\xbb\xbf") and h["Content-Type"] == "application/json"
    _, b, h = pd.multipart_lf("https://x/a", "p", pd.CANARY)
    assert b"\r\n" not in b and b"\n" in b and "multipart/form-data" in h["Content-Type"]


# -- assessors ---------------------------------------------------------------
def _r(status, length, canary=False, decoy=False):
    return pd.Resp(status=status, length=length, has_canary=canary, has_decoy=decoy)


def test_assess_decode_hit_and_misses():
    # canonical reflects the canary (endpoint echoes), quirk reflects it too from an
    # encoded-only payload ⇒ the app decoded the transform
    assert pd.assess_decode(_r(200, 40, canary=True), _r(200, 40, canary=True))["strong"]
    # endpoint not reflective ⇒ inconclusive
    assert pd.assess_decode(_r(200, 40, canary=False), _r(200, 40, canary=True)) is None
    # quirk did NOT decode ⇒ no hit (the safe case)
    assert pd.assess_decode(_r(200, 40, canary=True), _r(200, 40, canary=False)) is None


def test_assess_tolerance_gates_on_reflection_not_status():
    canonical = _r(200, 40, canary=True)
    rejected = _r(400, 5)                                  # invalid control rejected
    # standard-rejected quirk accepted + parsed, invalid rejected ⇒ hit
    assert pd.assess_tolerance(canonical, _r(200, 40, canary=True), rejected)["strong"] is False
    # KEY FIX: a lenient app that returns 200-empty on broken input (no canary) is a
    # REAL target, not an echoer ⇒ still assessed (not suppressed)
    assert pd.assess_tolerance(canonical, _r(200, 40, canary=True), _r(200, 9)) is not None
    # echo-everything (reflects the canary even from the invalid control) ⇒ suppressed
    assert pd.assess_tolerance(canonical, _r(200, 40, canary=True), _r(200, 40, canary=True)) is None
    # a standard parser rejects the quirk ⇒ secure, no hit
    assert pd.assess_tolerance(canonical, _r(400, 5), rejected) is None
    # accepted but our value not parsed ⇒ not a differential
    assert pd.assess_tolerance(canonical, _r(200, 40), rejected) is None
    # no usable baseline ⇒ None
    assert pd.assess_tolerance(_r(404, 9), _r(200, 40, canary=True), rejected) is None


def test_assess_precedence_is_informational_only():
    canonical = _r(200, 40, canary=True)
    # RFC-permitted duplicate accepted — report which value won, never a "strong" hit
    p = pd.assess_precedence(canonical, _r(200, 40, canary=True))
    assert p and "last-wins" in p["won"] and "strong" not in p
    assert "first-wins" in pd.assess_precedence(canonical, _r(200, 40, decoy=True))["won"]
    # rejected or unreflected ⇒ nothing to report
    assert pd.assess_precedence(canonical, _r(400, 5)) is None
    assert pd.assess_precedence(canonical, _r(200, 40)) is None


# -- end-to-end against the deliberately-lax /parserdiff endpoint ------------
@pytest.mark.asyncio
async def test_parser_diff_probe_detects_differentials(local_server, fresh_context):
    base, _ = local_server
    res = await srv.parser_diff_probe(target=f"{base}/parserdiff", param="p")
    lanes = {x["lane"] for x in res["lanes"]}
    # both decode lanes (strong) fire
    assert {"charset_utf7", "overlong_utf8"} <= lanes, res
    # the standard-parser-rejected tolerance lanes fire (comment/trailing/BOM/bare-LF)
    assert {"json_comment", "json_trailing", "json_bom", "multipart_lf"} <= lanes, res
    # RFC-permitted duplicates are informational precedence, NOT scored lanes
    prec = {x["lane"] for x in res["precedence"]}
    assert {"json_dupkey", "multipart_dup"} <= prec, res
    assert "json_dupkey" not in lanes and "multipart_dup" not in lanes, res
    assert res["verdict"] in ("likely", "confirmed"), res
    assert res["reflective"] is True


@pytest.mark.asyncio
async def test_parser_diff_probe_no_false_positive(local_server, fresh_context):
    base, _ = local_server
    res = await srv.parser_diff_probe(target=f"{base}/parserdiff-safe", param="p")
    assert res["lanes"] == [], res                          # no SCORED differential
    assert res["verdict"] == "unconfirmed", res
    # the FP fix in action: a STANDARD parser accepts RFC-permitted duplicate keys /
    # fields (last-wins) — that surfaces as a precedence LEAD and must NOT inflate the
    # verdict the way the old dup-key "tolerance" hit wrongly did
    assert {x["lane"] for x in res["precedence"]} == {"json_dupkey", "multipart_dup"}, res


@pytest.mark.asyncio
async def test_parser_diff_probe_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.parser_diff_probe(target=f"{base}/parserdiff", param="p")
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_parser_diff_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "parser_diff_probe" in tools
