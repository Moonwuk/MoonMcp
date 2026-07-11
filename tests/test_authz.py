"""Multi-step authorization / BOLA (IDOR) chains."""

import re

import pytest

from moonmcp import server as srv
from moonmcp.web import authz as az


# -- pure helpers -----------------------------------------------------------
def test_object_refs_path_and_query():
    refs = az.object_refs("https://x.test/api/orders/100?ref=550e8400-e29b-41d4-a716-446655440000&q=z")
    kinds = {(r.kind, r.value) for r in refs}
    assert ("numeric", "100") in kinds
    assert ("uuid", "550e8400-e29b-41d4-a716-446655440000") in kinds


def test_sibling_values_numeric_only():
    ref = az.ObjectRef("numeric", "100", "path:3")
    sibs = az.sibling_values(ref)
    assert "99" in sibs and "101" in sibs and "100" not in sibs
    assert az.sibling_values(az.ObjectRef("uuid", "abc", "path:1")) == []


def test_with_ref_replaces_path_and_query():
    ref = az.ObjectRef("numeric", "100", "path:3")
    assert az.with_ref("https://x.test/api/orders/100", ref, "101") == "https://x.test/api/orders/101"
    qref = az.ObjectRef("numeric", "5", "query:id")
    assert az.with_ref("https://x.test/get?id=5&x=1", qref, "6") == "https://x.test/get?id=6&x=1"


def test_extract_body_refs_from_json_and_hrefs():
    body = '{"id":100,"order_id":205,"link":"/invoices/77","uuid":"550e8400-e29b-41d4-a716-446655440000"}'
    got = set(az.extract_body_refs(body))
    assert {"205", "77"} <= got and "550e8400-e29b-41d4-a716-446655440000" in got


def test_looks_like_object_and_similar():
    assert az.looks_like_object(200, b'{"id":1,"data":"xxxx"}') is True
    assert az.looks_like_object(403, b"x" * 999) is False
    assert az.looks_like_object(200, b"ok") is False   # too short
    assert az.similar(b"hello world", b"hello world") == 1.0


# -- probe via fake apps ----------------------------------------------------
class _R:
    def __init__(self, status, body):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body
        self.error = None
        self.blocked_reason = None

    def text(self, limit=None):
        return self.body.decode()


class _VulnApp:
    """No object-level authz: any identity reads any /orders/<id>; owner body leaks next_id=205."""

    async def fetch(self, url, *, method="GET", headers=None, body=None,
                    suppress_auth=False, **kwargs):
        m = re.search(r"/orders/(\d+)", url)
        if not m:
            return _R(404, "not found")
        oid = m.group(1)
        is_anon = suppress_auth and not headers
        if is_anon:
            return _R(401, "unauthorized")     # anon blocked; B (headers) is not
        return _R(200, f'{{"id":{oid},"owner":"A","next_id":205,"data":"private-{oid}"}}')


class _SecureApp:
    """Only the owner (no suppress_auth) ever gets an object; everyone else 403."""

    async def fetch(self, url, *, method="GET", headers=None, body=None,
                    suppress_auth=False, **kwargs):
        if not re.search(r"/orders/(\d+)", url):
            return _R(404, "not found")
        if suppress_auth:
            return _R(403, "forbidden")
        return _R(200, '{"id":100,"owner":"A","next_id":205,"data":"secret"}')


@pytest.mark.asyncio
async def test_vuln_app_triggers_direct_sibling_and_multistep():
    res = await az.probe_bola(_VulnApp(), "https://x.test/orders/100", b_headers={"Cookie": "b=1"})
    kinds = {f["kind"] for f in res["findings"]}
    assert {"direct_bola", "sibling_idor", "multistep_bola"} <= kinds
    assert res["verdict"] == "review"
    # the multi-step chain reached the owner-exposed id 205
    assert any(f["kind"] == "multistep_bola" and f["owner_ref"] == "205" for f in res["findings"])


@pytest.mark.asyncio
async def test_secure_app_no_findings():
    res = await az.probe_bola(_SecureApp(), "https://x.test/orders/100", b_headers={"Cookie": "b=1"})
    assert res["findings"] == [] and res["verdict"] == "no_obvious_bola"


@pytest.mark.asyncio
async def test_no_refs_still_runs_direct_only():
    # a URL with no object id → no sibling/multistep, but direct still evaluated
    class _App:
        async def fetch(self, url, *, suppress_auth=False, **kw):
            return _R(200, "same-body-for-everyone-xxxxxxxx")
    res = await az.probe_bola(_App(), "https://x.test/me")
    assert res["refs_found"] == []
    assert any(f["kind"] == "direct_bola" for f in res["findings"])


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_authz_probe_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "authz_probe" in tools
