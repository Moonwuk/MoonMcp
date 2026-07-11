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
