"""GraphQL → NoSQL operator-injection probe — pure analysers + end-to-end eval."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.knowledge import injections as inj
from moonmcp.web import graphqli as gq


# -- pure helpers ------------------------------------------------------------
def test_build_body_transports_operator_as_variable():
    b = gq.build_body("query($moon:JSON){login(filter:$moon){token}}", "moon", {"$ne": None})
    obj = json.loads(b)
    assert obj["variables"] == {"moon": {"$ne": None}}
    assert "login(filter:$moon)" in obj["query"]


def test_data_present_detects_resolver_payload():
    assert gq.data_present('{"data":{"login":{"token":"x"}}}') is True
    assert gq.data_present('{"data":{"login":null}}') is False          # auth fail
    assert gq.data_present('{"data":null,"errors":[{"message":"x"}]}') is False
    assert gq.data_present('{"data":{"users":[]}}') is False            # empty list
    assert gq.data_present("not json") is False


def test_is_rejected_flags_strict_typing_only():
    assert gq.is_rejected('{"errors":[{"message":"Expected type String, found {}"}]}') is True
    assert gq.is_rejected('{"errors":[{"message":"got invalid value {}"}]}') is True
    # a resolver-side error is NOT a type rejection
    assert gq.is_rejected('{"errors":[{"message":"CastError: Cast to string failed"}]}') is False
    assert gq.is_rejected('{"data":{"login":{"token":"x"}}}') is False


def _r(status, length, data=False, rejected=False, session=False):
    return gq.Resp(status=status, length=length, data=data, rejected=rejected, session=session)


def test_assess_operator_data_flip_is_strong():
    control = (_r(200, 30, data=False), _r(200, 30, data=False))
    twin = (_r(200, 120, data=True), _r(200, 120, data=True))
    hit = gq.assess_operator(control, twin)
    assert hit and hit["strong"] is True
    assert any("auth/record flip" in r for r in hit["reasons"])


def test_assess_operator_rejects_noise_and_no_flip():
    control = (_r(200, 30), _r(200, 30))
    # non-reproducible twin ⇒ noise
    assert gq.assess_operator(control, (_r(200, 120, data=True), _r(200, 30))) is None
    # identical to control ⇒ no differential
    assert gq.assess_operator(control, (_r(200, 30), _r(200, 30))) is None


def test_assess_operator_type_rejection_is_never_a_hit():
    # a strict String variable ⇒ the object 400s (a coercion rejection). A status
    # change to a rejection must NOT be scored as an auth flip (contract inversion FP).
    control = (_r(200, 30, data=False), _r(200, 30, data=False))
    twin = (_r(400, 90, rejected=True), _r(400, 90, rejected=True))
    assert gq.assess_operator(control, twin) is None
    # a resolver that crashes (200→500) is likewise not injection
    assert gq.assess_operator(control, (_r(500, 90), _r(500, 90))) is None


def test_assess_operator_requires_reproducible_control():
    # a flaky/LB control must not be trusted even if the twin is internally stable
    flaky_control = (_r(401, 20, data=False), _r(200, 80, data=True))
    twin = (_r(200, 80, data=True), _r(200, 80, data=True))
    assert gq.assess_operator(flaky_control, twin) is None


def test_assess_operator_directional_status_and_cookie_flips():
    # denied→success is an auth bypass; success→denied is not
    denied = (_r(401, 20, data=False), _r(401, 20, data=False))
    ok = (_r(200, 20, data=False), _r(200, 20, data=False))
    assert gq.assess_operator(denied, ok)["strong"] is True
    assert gq.assess_operator(ok, denied) is None
    # a session cookie for the object but not the control = strong flip (body shape same)
    ctrl = (_r(200, 30, data=True, session=False), _r(200, 30, data=True, session=False))
    twin = (_r(200, 30, data=True, session=True), _r(200, 30, data=True, session=True))
    hit = gq.assess_operator(ctrl, twin)
    assert hit and hit["strong"] and any("cookie" in r for r in hit["reasons"])


def test_mongoose_casterror_signature_added_to_kb():
    hits = inj.match_signatures("CastError: Cast to string failed for value \"[object Object]\"",
                                class_id="nosqli")
    assert any("Mongoose" in h["technology"] for h in hits), hits


# -- end-to-end against the deliberately-vulnerable /gqlnosqli resolver ------
_Q = "query($moon:JSON){login(filter:$moon){token}}"


@pytest.mark.asyncio
async def test_graphql_nosqli_detects_operator_bypass(local_server, fresh_context):
    base, _ = local_server
    res = await srv.graphql_nosqli(target=f"{base}/gqlnosqli", query=_Q)
    ops = {h["operator"] for h in res["operator_hits"]}
    assert {"$ne", "$gt", "$in", "$nin"} <= ops, res
    assert any(h["strong"] for h in res["operator_hits"]), res
    assert res["verdict"] in ("likely", "confirmed"), res
    assert res["strictly_typed_variable"] is False


@pytest.mark.asyncio
async def test_graphql_nosqli_strict_400_is_not_a_hit(local_server, fresh_context):
    # a spec-compliant server 400s the object (variable-coercion error) — this must be
    # reported as a strictly-typed variable, NEVER as a status-flip injection hit
    base, _ = local_server
    res = await srv.graphql_nosqli(target=f"{base}/gqlnosqli-safe", query=_Q)
    assert res["operator_hits"] == [], res
    assert res["strictly_typed_variable"] is True, res
    assert res["verdict"] == "unconfirmed", res


@pytest.mark.asyncio
async def test_graphql_nosqli_detects_large_body_flip(local_server, fresh_context):
    # the winning body exceeds the 50k slice — detection must read the full body
    base, _ = local_server
    res = await srv.graphql_nosqli(target=f"{base}/gqlnosqli-big",
                                   query="query($moon:JSON){users(where:$moon){id}}")
    assert res["operator_hits"], res
    assert res["verdict"] in ("likely", "confirmed"), res


@pytest.mark.asyncio
async def test_graphql_nosqli_detects_cookie_only_flip(local_server, fresh_context):
    # auth flip signalled only by Set-Cookie, body shape unchanged
    base, _ = local_server
    res = await srv.graphql_nosqli(target=f"{base}/gqlnosqli-cookie", query=_Q)
    assert res["operator_hits"], res
    assert any("cookie" in r for h in res["operator_hits"] for r in h["reasons"]), res


@pytest.mark.asyncio
async def test_graphql_nosqli_refuses_mutation(local_server, fresh_context):
    # detection-only: a mutation would run writes with match-everything filters
    base, _ = local_server
    res = await srv.graphql_nosqli(target=f"{base}/gqlnosqli",
                                   query="mutation($moon:JSON){deleteUsers(filter:$moon){count}}")
    assert res["error"] == "invalid_input", res


@pytest.mark.asyncio
async def test_graphql_nosqli_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.graphql_nosqli(target=f"{base}/gqlnosqli", query=_Q)
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_graphql_nosqli_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "graphql_nosqli" in tools
