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


class _SoftApp:
    """Soft-404 / SPA: every path — existing or not — returns the same 200 shell, so the
    id is not object-scoped. The old sweep flagged direct_bola + sibling_idor here."""

    async def fetch(self, url, *, method="GET", headers=None, body=None,
                    suppress_auth=False, **kwargs):
        return _R(200, "<html><body>App shell — client-side routed, id ignored xxxxxxxx</body></html>")


@pytest.mark.asyncio
async def test_soft_404_app_no_bola_false_positive():
    # The negative control (a nonexistent id returns the same object-like shell) proves
    # the endpoint isn't object-scoped, so every BOLA signal is suppressed.
    res = await az.probe_bola(_SoftApp(), "https://x.test/orders/100", b_headers={"Cookie": "b=1"})
    assert res["findings"] == []
    assert res["verdict"] == "no_obvious_bola"
    assert "not object-scoped" in (res.get("note") or "")


# A large shared HTML chrome (>4 KB) with a small per-id data block — the case where a
# 4 KB similarity window sees only identical chrome and would wrongly call a real object a
# "shell", suppressing genuine IDOR. The jitter-aware length/content control must catch it.
_CHROME = "<html><head>" + "<meta charset=utf-8>" * 400 + "</head><body><nav>menu</nav>"


class _ChromeIDORApp:
    """Object-scoped HTML app: big shared chrome + a small per-id data block; absent ids
    soft-404 to a 'not found' shell (same chrome); neighbours return other users' data."""

    async def fetch(self, url, *, method="GET", headers=None, body=None, suppress_auth=False, **kw):
        m = re.search(r"/orders/(\d+)", url)
        oid = m.group(1) if m else None
        if oid in ("100", "99", "101", "205"):
            return _R(200, _CHROME + f"<div id=data>ORDER {oid} for customer {oid}</div></body></html>")
        return _R(200, _CHROME + "<div id=data>Order not found</div></body></html>")


@pytest.mark.asyncio
async def test_chrome_heavy_idor_is_not_suppressed():
    # regression: the object data (<40B) is dwarfed by >4 KB shared chrome, so a 4 KB
    # similarity control called every id "the same shell" and dropped the real IDOR.
    res = await az.probe_bola(_ChromeIDORApp(), "https://x.test/orders/100", b_headers={"Cookie": "b=1"})
    assert "sibling_idor" in {f["kind"] for f in res["findings"]}


class _DecorativeRefIDORApp:
    """/reports/<year>/invoice/<id>: the leading year is decorative (ignored); the invoice
    id IS object-scoped and absent ones 404. Neighbours are other orgs' invoices."""

    async def fetch(self, url, *, method="GET", headers=None, body=None, suppress_auth=False, **kw):
        m = re.search(r"/invoice/(\d+)", url)
        iid = m.group(1) if m else None
        if iid in ("778899", "778898", "778900", "1", "2"):
            return _R(200, f'{{"invoice":{iid},"org":"acme","total":42}}')
        return _R(404, "not found")


class _DynSoft404IDORApp:
    """Vulnerable horizontal IDOR + a DYNAMIC soft-404: absent ids return a 200 shell whose
    length varies per request (a 'recommended for you' block), real ids return distinct orders.
    The byte-unstable control can't PROVE a shell, so a real object must not be suppressed."""

    def __init__(self):
        self._n = 0

    async def fetch(self, url, *, method="GET", headers=None, body=None, suppress_auth=False, **kw):
        m = re.search(r"/orders/(\d+)", url)
        oid = m.group(1) if m else None
        if oid in ("99", "100", "101"):
            return _R(200, f'{{"order":{oid},"buyer":"user{oid}","total":{oid}0}}')
        self._n += 1                                   # dynamic soft-404 shell: varying length
        return _R(200, "Order not found. Recommended for you: " + "x" * (self._n % 40))


@pytest.mark.asyncio
async def test_dynamic_soft404_idor_is_surfaced_not_missed():
    # regression (HIGH FN): a jittery soft-404 both widens the length band and defeats content
    # comparison; the redesign must not silently suppress the real IDOR — an unprovable shell is
    # surfaced (low-confidence / soft_404_suspected), never dropped.
    res = await az.probe_bola(_DynSoft404IDORApp(), "https://x.test/orders/100", b_headers={"Cookie": "b=1"})
    assert res["findings"], "real IDOR on a dynamic soft-404 endpoint must not be silently missed"


@pytest.mark.asyncio
async def test_decorative_leading_ref_does_not_suppress_object_sweep():
    # regression: the control only probed refs[0] (the year) and globally suppressed the
    # sweep of the real object ref. It must now sweep the invoice ref independently.
    res = await az.probe_bola(_DecorativeRefIDORApp(),
                              "https://x.test/reports/2024/invoice/778899", b_headers={"Cookie": "b=1"})
    hits = [f for f in res["findings"] if f["kind"] == "sibling_idor"]
    assert any(f["ref"] == "778899" for f in hits)


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
