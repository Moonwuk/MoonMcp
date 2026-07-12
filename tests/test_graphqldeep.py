"""Deep GraphQL probing (graphql_probe) — batch abuse, suggestions, aliases."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.web import graphqldeep as gd


# ── pure parsers ────────────────────────────────────────────────────────────
def test_build_batch():
    body = json.loads(gd.build_batch("{__typename}", 4))
    assert isinstance(body, list) and len(body) == 4
    assert all(b == {"query": "{__typename}"} for b in body)
    assert len(json.loads(gd.build_batch("{x}", 1))) == 2  # floored to 2


def test_parse_batch_response():
    arr = json.dumps([{"data": {"__typename": "Query"}}] * 3)
    assert gd.parse_batch_response(arr, 3) == {"batched": True, "count": 3}
    # a single object (batching rejected) is not batched
    assert gd.parse_batch_response(json.dumps({"data": {}}), 3)["batched"] is False
    assert gd.parse_batch_response("not json", 3)["batched"] is False


def test_parse_suggestions():
    msg = json.dumps({"errors": [{"message":
          'Cannot query field "__typenamee" on type "Query". Did you mean "__typename"?'}]})
    assert gd.parse_suggestions(msg) == ["__typename"]
    multi = 'Did you mean "user" or "users"?'
    assert gd.parse_suggestions(multi) == ["user", "users"]
    assert gd.parse_suggestions("no hints here") == []


# ── deep_probe over a body-aware fake client ────────────────────────────────
class _Resp:
    def __init__(self, status, text=""):
        self.status = status
        self._t = text
        self.error = None

    def text(self, limit=None):
        return self._t


class _FakeGql:
    """A GraphQL server that batches, suggests on typos, and honours aliases."""

    def __init__(self, is_graphql=True):
        self.is_graphql = is_graphql

    async def fetch(self, url, *, method="GET", headers=None, body=None, **kw):
        b = (body or b"").decode()
        if not self.is_graphql:
            return _Resp(200, "<html>not graphql</html>")
        if b.startswith("["):
            n = len(json.loads(b))
            return _Resp(200, json.dumps([{"data": {"__typename": "Query"}}] * n))
        if "__typenamee" in b:
            return _Resp(200, json.dumps({"errors": [{"message":
                'Cannot query field "__typenamee" on type "Query". Did you mean "__typename"?'}]}))
        if "a:__typename" in b:
            return _Resp(200, json.dumps({"data": {"a": "Query", "b": "Query"}}))
        return _Resp(200, json.dumps({"data": {"__typename": "Query"}}))


@pytest.mark.asyncio
async def test_deep_probe_detects_batch_suggestions_aliases():
    res = await gd.deep_probe(_FakeGql(), "http://t.example/graphql", batch_n=5)
    assert res.is_graphql is True
    assert res.batching == {"batched": True, "count": 5}
    assert res.suggestions_enabled is True and res.recovered_names == ["__typename"]
    assert res.aliases_enabled is True
    kinds = {ld["kind"] for ld in res.leads}
    assert {"graphql_batching", "graphql_field_suggestions"} <= kinds
    assert any("BOLA" in r for r in res.review)


@pytest.mark.asyncio
async def test_deep_probe_non_graphql():
    res = await gd.deep_probe(_FakeGql(is_graphql=False), "http://t.example/x")
    assert res.is_graphql is False
    assert res.review


@pytest.mark.asyncio
async def test_graphql_probe_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "graphql_probe" in tools
