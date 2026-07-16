"""Tests for the engagement auth context and the access-control / IDOR diff."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.auth import AuthContext


def test_auth_context_unit():
    a = AuthContext()
    assert not a.is_set()
    a.set_bearer("abc.def.ghi")
    a.set_cookie_string("session=xyz; theme=dark")
    h = a.merged_headers()
    assert h["Authorization"] == "Bearer abc.def.ghi"
    assert h["Cookie"] == "session=xyz; theme=dark"
    # redaction hides credential values
    red = a.redacted()
    assert red["set"] is True
    assert "abc.def.ghi" not in json.dumps(red)
    a.clear()
    assert not a.is_set()


@pytest.mark.asyncio
async def test_auth_headers_reach_the_server(local_server, fresh_context):
    base, _ = local_server
    await srv.auth_set(bearer="tok123", cookie="sid=deadbeef", headers={"X-Team": "red"})
    # fetch /echo directly through the shared client — auth must be merged in
    r = await fresh_context.http.fetch(f"{base}/echo")
    echoed = json.loads(r.text())
    assert echoed.get("authorization") == "Bearer tok123"
    assert "sid=deadbeef" in echoed.get("cookie", "")
    assert echoed.get("x-team") == "red"
    # the anonymous (suppress_auth) leg must NOT carry the bearer
    anon = json.loads((await fresh_context.http.fetch(f"{base}/echo", suppress_auth=True)).text())
    assert "authorization" not in anon
    # server_status reflects (redacted) auth
    st = await srv.server_status()
    assert st["auth_context"]["set"] is True
    await srv.auth_clear()
    assert (await srv.server_status())["auth_context"]["set"] is False


@pytest.mark.asyncio
async def test_suppress_auth_on_anonymous_leg(local_server, fresh_context):
    base, _ = local_server
    await srv.auth_set(bearer="secret-A")
    # authz_probe(direct_only=True): the anonymous leg must NOT carry the bearer.
    # (the local server ignores auth, so all identities get 200 — we assert the
    # tool ran all identities and produced a structured verdict)
    res = await srv.authz_probe(target=f"{base}/echo", direct_only=True)
    assert "auth_A" in res["identities"] and "anonymous" in res["identities"]
    assert res["identities"]["auth_A"]["status"] == 200
    assert res["identities"]["anonymous"]["status"] == 200
    assert "verdict" in res
    await srv.auth_clear()


@pytest.mark.asyncio
async def test_access_control_flags_shared_response(local_server, fresh_context):
    base, _ = local_server
    # local server returns the same body regardless of identity → the diff should
    # flag that anonymous gets a response identical to the authenticated one.
    await srv.auth_set(bearer="secret-A")
    res = await srv.authz_probe(target=base, direct_only=True)
    assert res["verdict"] == "review"
    assert any("access control" in c.lower() or "idor" in c.lower() for c in res["concerns"])
    await srv.auth_clear()


@pytest.mark.asyncio
async def test_auth_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    for n in ("auth_set", "auth_clear", "authz_probe"):
        assert n in tools
    assert "access_control_check" not in tools   # folded into authz_probe(direct_only=/method=/body=)


def test_redacted_masks_credential_header_under_any_name():
    from moonmcp.auth import AuthContext
    a = AuthContext()
    a.update_headers({"X-Auth-Token": "supersecretvalue123", "User-Agent": "moonmcp/1.0"})
    red = a.redacted()
    assert red["headers"]["X-Auth-Token"] != "supersecretvalue123"   # credential masked
    assert red["headers"]["User-Agent"] == "moonmcp/1.0"             # benign header visible
