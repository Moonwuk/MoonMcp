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
    pairs = az.extract_body_refs(body)
    vals = {v for v, _c in pairs}
    assert {"205", "77"} <= vals and "550e8400-e29b-41d4-a716-446655440000" in vals
    # each id carries the collection it was named under (field `_id` prefix / href segment)
    by_val = dict(pairs)
    assert by_val["205"] == "order"       # "order_id"  -> order
    assert by_val["77"] == "invoices"     # /invoices/77 -> invoices
    assert by_val["100"] == ""            # bare "id"   -> generic


def test_collection_compatibility_rules():
    # generic relationship pointers and bare ids chain into any slot
    assert az._collection_compatible("", "orders") is True
    assert az._collection_compatible("next", "orders") is True
    # same collection, singular/plural-insensitive
    assert az._collection_compatible("order", "orders") is True
    assert az._collection_compatible("orders", "order") is True
    # a foreign collection must not chain into this slot
    assert az._collection_compatible("product", "orders") is False
    assert az._collection_compatible("user", "orders") is False


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


# -- routing: body truthiness, not `is not None` ----------------------------
@pytest.mark.asyncio
async def test_authz_probe_empty_body_runs_bola_chain(fresh_context, local_server):
    base, _ = local_server
    # A GET with an EMPTY-STRING body carries no payload, so it must run the full
    # multi-step BOLA chain — NOT the single-request cross-identity diff (which is
    # reserved for non-GET / a real body / direct_only). The two return shapes are
    # distinct: the chain carries "note"/"refs_found"; the diff carries "identities".
    res = await srv.authz_probe(target=f"{base}/orders/100", body="")
    assert "identities" not in res      # would appear iff misrouted to the direct diff
    assert "note" in res                # BOLA-chain shape


@pytest.mark.asyncio
async def test_authz_probe_real_body_runs_direct_diff(fresh_context, local_server):
    base, _ = local_server
    # A real body legitimately routes to the single-request cross-identity diff.
    res = await srv.authz_probe(target=f"{base}/echo", method="POST", body='{"x":1}')
    assert "identities" in res
    assert res["method"] == "POST"


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_authz_probe_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "authz_probe" in tools


def test_similar_compares_head_and_tail_not_just_first_4kib():
    from moonmcp.web.authz import similar
    # Two server-rendered pages: identical >4 KiB nav/shell, then a substantial block of
    # DIFFERENT per-object data below it (total > 8 KiB so head+tail sampling engages).
    shell = b"N" * 5000                                   # shared shell fills the first 4 KiB
    a = shell + b"A" * 4000                               # object A's distinct data
    b = shell + b"B" * 4000                               # object B's distinct data
    assert similar(a[:4096], b[:4096]) == 1.0             # first-4KiB-only would call them identical
    assert similar(a, b) < 0.9                            # head+tail sees the differing tail
    assert similar(a, a) == 1.0                           # truly identical bodies still 1.0


class _SoftApp:
    """Soft-200 catch-all: returns the SAME object-like body for EVERY id (no real
    per-object data). The sibling sweep must not report a false IDOR against it."""

    async def fetch(self, url, *, method="GET", headers=None, body=None,
                    suppress_auth=False, **kwargs):
        return _R(200, '{"page":"catch-all","content":"' + "x" * 40 + '"}')


@pytest.mark.asyncio
async def test_sibling_sweep_suppressed_on_soft_200_catch_all():
    # A nonexistent-id control returns the same body as every neighbour → soft-200,
    # so no false sibling/chained IDOR is reported (real IDOR still fires — see _VulnApp).
    res = await az.probe_bola(_SoftApp(), "https://x.test/orders/100", b_headers={"Cookie": "b=1"})
    kinds = {f["kind"] for f in res["findings"]}
    assert "sibling_idor" not in kinds
    assert "multistep_bola" not in kinds


class _CollectionApp:
    """Object-level authz IS broken, but only along its OWN collection. /orders/100
    (owner) exposes two ids: order_id=301 (SAME collection) and product_id=205 (a
    DIFFERENT collection that merely shares the number 205). A non-owner can read both
    /orders/301 and /orders/205. The multi-step chain must inject the ORDER id (a real
    chained IDOR) but NOT the PRODUCT id — /orders/205 is an unrelated object reached by
    a same-number coincidence, not by chaining the exposed product reference."""

    async def fetch(self, url, *, method="GET", headers=None, body=None,
                    suppress_auth=False, **kwargs):
        m = re.search(r"/orders/(\d+)", url)
        if not m:
            return _R(404, "not found")
        oid = m.group(1)
        if not suppress_auth and oid == "100":            # owner's object exposes both ids
            # product_id is listed FIRST: the old order-blind chain would grab 205 and stop
            # before ever reaching the real order_id — so this ordering makes the test fail
            # loudly if the collection filter regresses.
            return _R(200, '{"id":100,"owner":"A","product_id":205,"order_id":301,'
                           '"data":"owner-order-100-xxxxxxxx"}')
        if suppress_auth and oid in ("205", "301"):       # distinct real objects, no authz
            return _R(200, f'{{"id":{oid},"owner":"Z","data":"distinct-object-{oid}-xxxxxxxx"}}')
        return _R(403, "forbidden")                       # everything else blocked (keeps signals clean)


@pytest.mark.asyncio
async def test_multistep_chains_same_collection_but_not_a_foreign_id():
    res = await az.probe_bola(_CollectionApp(), "https://x.test/orders/100",
                              b_headers={"Cookie": "b=1"})
    owner_refs = {f["owner_ref"] for f in res["findings"] if f["kind"] == "multistep_bola"}
    assert "301" in owner_refs        # TP: same-collection order_id → chained IDOR still fires
    assert "205" not in owner_refs    # FP suppressed: product_id must not chain into /orders/<id>
