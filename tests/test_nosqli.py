"""NoSQL (MongoDB) operator-injection probe — pure analysers + end-to-end eval."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.web import nosqli as nq


# -- pure request builders ---------------------------------------------------
def test_scalar_request_get_and_post():
    u, b, h = nq.scalar_request("https://x/login", "user", nq.CONTROL, "GET")
    assert f"user={nq.CONTROL}" in u and b is None and h == {}
    u, b, h = nq.scalar_request("https://x/login", "user", nq.CONTROL, "POST")
    assert b == f"user={nq.CONTROL}".encode() and u == "https://x/login"


def test_bracket_request_places_operator_key():
    u, b, _ = nq.bracket_request("https://x/login?user=old", "user", "$ne", nq.CONTROL, "GET")
    # the operator key is present and the prior scalar `user=old` is dropped
    assert "user%5B%24ne%5D" in u and "user=old" not in u
    u, b, _ = nq.bracket_request("https://x/login", "user", "$gt", "", "POST")
    assert b == b"user%5B%24gt%5D="


def test_json_request_shapes_operator_object():
    u, b, h = nq.json_request("https://x/login", "user", {"$ne": None})
    assert h["Content-Type"] == "application/json"
    assert json.loads(b) == {"user": {"$ne": None}}


def test_session_cookie_detection():
    assert nq.has_session_cookie(["session=abc; Path=/"])
    assert nq.has_session_cookie(["connect.sid=xyz"])
    assert not nq.has_session_cookie(["theme=dark"])
    assert not nq.has_session_cookie([])


# -- pure assessment ---------------------------------------------------------
def _r(status, length, cookie=False):
    return nq.Resp(status=status, length=length, session_cookie=cookie)


def test_assess_operator_strong_status_flip():
    control = (_r(401, 30), _r(401, 30))
    twin = (_r(200, 300, cookie=True), _r(200, 300, cookie=True))
    hit = nq.assess_operator(control, twin)
    assert hit and hit["strong"] is True
    assert any("401→200" in s for s in hit["reasons"])
    assert any("session" in s.lower() for s in hit["reasons"])


def test_assess_operator_rejects_non_reproducible():
    control = (_r(401, 30), _r(401, 30))
    # the two twin sends disagree → noise, not a real differential
    assert nq.assess_operator(control, (_r(200, 300), _r(401, 30))) is None


def test_assess_operator_no_flip_is_none():
    control = (_r(200, 100), _r(200, 100))
    assert nq.assess_operator(control, (_r(200, 100), _r(200, 100))) is None


def test_assess_operator_length_only_needs_stable_control():
    control = (_r(200, 100), _r(200, 100))
    twin = (_r(200, 400), _r(200, 400))          # same status, much longer body
    hit = nq.assess_operator(control, twin)
    assert hit and hit["strong"] is False and any("bytes" in r for r in hit["reasons"])
    # if the control itself is unstable, a length-only delta is NOT trusted
    assert nq.assess_operator((_r(200, 100), _r(200, 180)), twin) is None


def test_assess_where_boolean_oracle():
    hit = nq.assess_where((_r(200, 300), _r(200, 300)), (_r(401, 30), _r(401, 30)))
    assert hit and hit["status_changed"] is True
    # stable identical true/false ⇒ no oracle
    assert nq.assess_where((_r(200, 300), _r(200, 300)), (_r(200, 300), _r(200, 300))) is None
    # unstable pair ⇒ rejected
    assert nq.assess_where((_r(200, 300), _r(200, 500)), (_r(401, 30), _r(401, 30))) is None


def test_stable_tolerates_small_jitter():
    # a few-byte nonce/counter delta between two identical sends is NOT instability
    assert nq._stable(_r(200, 1000), _r(200, 1012)) is True     # 12 < ~50 (5%) tolerance
    assert nq._stable(_r(200, 1000), _r(200, 1400)) is False    # 400 >> tolerance
    # and a true/false differential must EXCEED the jitter floor, not differ by a byte
    assert nq.assess_where((_r(200, 1000), _r(200, 1008)),
                           (_r(200, 1000), _r(200, 1006))) is None


def test_assess_operator_bracket_flip_rejected_when_benign_nested_flips_too():
    # non-Mongo: param[$ne] and the benign param[zz] both make the framework error
    # the same way (object where a string was expected) — param parsing, not NoSQLi.
    control = (_r(401, 30), _r(401, 30))
    twin = (_r(500, 60), _r(500, 60))            # operator bracket flips to 500
    nested = (_r(500, 60), _r(500, 60))          # benign nested key ALSO flips to 500
    assert nq.assess_operator(control, twin, nested=nested) is None
    # but a Mongo app where the benign nested key does NOT flip (stays like control)
    # keeps the operator flip as a real hit
    nested_benign = (_r(401, 30), _r(401, 30))
    hit = nq.assess_operator(control, twin, nested=nested_benign)
    assert hit and hit["strong"] is True


# -- end-to-end against the deliberately-vulnerable /nosqli login ------------
@pytest.mark.asyncio
async def test_nosqli_probe_detects_operator_bypass(local_server, fresh_context):
    base, _ = local_server
    res = await srv.nosqli_probe(target=f"{base}/nosqli", param="user")
    assert res["verdict"] in ("likely", "confirmed"), res
    variants = {h["variant"] for h in res["operator_hits"]}
    assert any(v.startswith("json:") for v in variants), res
    assert any(v.startswith("bracket:") for v in variants), res
    assert any(h["strong"] for h in res["operator_hits"]), res
    assert res["where_oracle"] and res["where_oracle"]["status_changed"], res


@pytest.mark.asyncio
async def test_nosqli_probe_no_false_positive(local_server, fresh_context):
    base, _ = local_server
    res = await srv.nosqli_probe(target=f"{base}/nosqli-safe", param="user")
    assert res["operator_hits"] == [] and res["where_oracle"] is None
    assert res["verdict"] == "unconfirmed"


@pytest.mark.asyncio
async def test_nosqli_probe_no_fp_on_non_mongo_bracket_parsing(local_server, fresh_context):
    # A framework that turns any bracketed param into an object errors identically for
    # param[$ne] and the benign param[zz]; that is param parsing, not Mongo injection.
    base, _ = local_server
    res = await srv.nosqli_probe(target=f"{base}/nosqli-bracketparse", param="user")
    assert not any(h["variant"].startswith("bracket:") for h in res["operator_hits"]), res
    assert res["verdict"] == "unconfirmed", res


@pytest.mark.asyncio
async def test_nosqli_probe_no_fp_on_json_only_api(local_server, fresh_context):
    # A JSON-only API 400s a form body but 200s ANY JSON body (scalar or operator).
    # The JSON operator lane must use a JSON *scalar* baseline (content-type-matched),
    # not the form/GET scalar control — else the content-type status flip (form 400 →
    # JSON 200) is misread as a $ne injection. Regression for that false positive.
    base, _ = local_server
    res = await srv.nosqli_probe(target=f"{base}/nosqli-jsononly", param="user")
    assert not any(h["variant"].startswith("json:") for h in res["operator_hits"]), res
    assert res["verdict"] == "unconfirmed", res


@pytest.mark.asyncio
async def test_nosqli_probe_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.nosqli_probe(target=f"{base}/nosqli", param="user")
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_nosqli_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "nosqli_probe" in tools
