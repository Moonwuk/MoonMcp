"""Server-side prototype pollution (SSPP) — safe reversible `json spaces` differential."""

import http.client
import json
import re

import pytest

from moonmcp import server as srv
from moonmcp.web import sspp


# -- pure analysers ---------------------------------------------------------
def test_looks_json_and_pretty():
    assert sspp.looks_json('{"a":1}') and sspp.looks_json('[1,2]')
    assert not sspp.looks_json("<html>") and not sspp.looks_json("")
    assert not sspp.is_pretty_printed('{"a": 1, "b": 2}')      # compact single line
    assert sspp.is_pretty_printed('{\n          "a": 1\n}')    # json-spaces indentation


def test_assess_transition_is_causal():
    compact = '{"a": 1, "b": 2}'
    pretty = json.dumps({"a": 1, "b": 2}, indent=10)
    # the full causal triple: compact -> pretty (larger) -> compact again
    assert sspp.assess_transition(compact, pretty, compact) is True
    # any missing leg fails (no pollution effect / already pretty / didn't revert)
    assert sspp.assess_transition(compact, compact, compact) is False
    assert sspp.assess_transition(pretty, pretty, pretty) is False
    assert sspp.assess_transition(compact, pretty, pretty) is False   # never cleaned up
    assert sspp.assess_transition("<html>", pretty, compact) is False  # baseline not JSON


def test_pretty_detection_covers_primitive_arrays():
    # a top-level array of numeric primitives, pretty-printed at the injected width, is a real
    # SSPP tell — its indented lines start with a digit, which a token-restricted regex misses
    pretty_nums = json.dumps([1, 2, 3], indent=sspp.INJECT_SPACES)
    assert sspp.is_pretty_printed(pretty_nums)
    assert sspp.has_injected_indent(pretty_nums)
    assert sspp.assess_transition("[1,2,3]", pretty_nums, "[1,2,3]") is True


def test_benign_other_width_pretty_is_not_confirmed():
    # a benign pretty-printer at a DIFFERENT width (e.g. json spaces: 2) is ambient formatting
    # drift, not our injection — it IS pretty but NOT at our width, so it must not confirm
    other = json.dumps({"a": 1, "b": 2}, indent=2)
    assert sspp.is_pretty_printed(other)
    assert not sspp.has_injected_indent(other)
    assert sspp.assess_transition('{"a":1}', other, '{"a":1}') is False
    # a width-2 doc nested deep enough that some INNER level reaches 10 spaces must still fail:
    # the level-1 anchor (2 spaces) is what distinguishes it from our width-10 injection
    deep = json.dumps({"a": {"b": {"c": {"d": {"e": 1}}}}}, indent=2)
    assert sspp.is_pretty_printed(deep) and not sspp.has_injected_indent(deep)


def test_looks_json_survives_deeply_nested_hostile_body():
    # a malformed/hostile target body that would blow the recursion limit must not crash the
    # probe — looks_json returns False instead of propagating RecursionError
    assert sspp.looks_json("[" * 60000) is False


def test_query_vectors_encode_to_wire_safe_urls():
    # the raw query vectors carry a literal space that http.client rejects; encode_query makes
    # them wire-safe while preserving the __proto__[json spaces] path for Express's qs parser
    for _n, pollute, cleanup in sspp.QUERY_VECTORS:
        for raw in (pollute, cleanup):
            enc = sspp.encode_query(raw)
            assert " " not in enc and not re.search(r"[\x00-\x20\x7f]", enc)
            assert "[" in enc and "]" in enc and "json" in enc and "spaces" in enc


# -- probe against fake stateful apps ---------------------------------------
class _R:
    def __init__(self, status, text):
        self.status = status
        self._text = text
        self.body = text.encode()

    def text(self, limit=None):
        return self._text


class _VulnExpress:
    """A deliberately-vulnerable Express-like app: a POST body's `__proto__`/
    `constructor.prototype` `json spaces` deep-merges into the global render setting, so
    every subsequent res.json() GET is indented by that many spaces."""

    def __init__(self):
        self.json_spaces = 0
        self.data = {"ok": True, "items": [1, 2, 3], "user": {"id": 7, "name": "alice"}}

    async def fetch(self, url, *, method="GET", body=None, headers=None, **kw):
        if method == "POST" and body:
            try:
                obj = json.loads(body)
            except (ValueError, TypeError):
                obj = {}
            proto = obj.get("__proto__") or (obj.get("constructor") or {}).get("prototype") or {}
            if "json spaces" in proto:
                self.json_spaces = int(proto["json spaces"])
            return _R(200, "{}")
        return _R(200, json.dumps(self.data, indent=self.json_spaces or None))


class _SafeApp:
    """Ignores __proto__ entirely — res.json() is always compact (no SSPP)."""

    def __init__(self):
        self.data = {"ok": True, "items": [1, 2, 3]}

    async def fetch(self, url, *, method="GET", body=None, headers=None, **kw):
        if method == "POST":
            return _R(200, "{}")
        return _R(200, json.dumps(self.data))       # always compact


@pytest.mark.asyncio
async def test_probe_confirms_vulnerable_and_leaves_it_clean():
    app = _VulnExpress()
    res = await sspp.probe_sspp(app, "https://x.test/api/profile")
    assert res["verdict"] == "confirmed"
    assert any(f["vector"] == "__proto__" and f["verdict"] == "confirmed" for f in res["findings"])
    # cleanup ran: the app is no longer polluted after the probe
    assert app.json_spaces == 0


@pytest.mark.asyncio
async def test_probe_safe_app_no_finding():
    res = await sspp.probe_sspp(_SafeApp(), "https://x.test/api/profile")
    assert res["findings"] == [] and res["verdict"] == "no_sspp"


@pytest.mark.asyncio
async def test_probe_non_json_endpoint_is_skipped():
    class _Html:
        async def fetch(self, url, **kw):
            return _R(200, "<html><body>hi</body></html>")
    res = await sspp.probe_sspp(_Html(), "https://x.test/")
    assert res["verdict"] == "not_json"


@pytest.mark.asyncio
async def test_probe_already_pretty_is_unobservable():
    class _AlwaysPretty:
        async def fetch(self, url, *, method="GET", **kw):
            if method == "POST":
                return _R(200, "{}")
            return _R(200, json.dumps({"a": 1, "b": 2}, indent=2))
    res = await sspp.probe_sspp(_AlwaysPretty(), "https://x.test/api")
    assert res["verdict"] == "already_pretty"


@pytest.mark.asyncio
async def test_probe_query_fallback_does_not_crash_on_validating_client():
    # a client that validates URLs like the real http.client (rejects raw control chars). The
    # POST body vectors don't fire, so the probe reaches the query fallback — with the query
    # string percent-encoded it must complete and return no_sspp, not raise InvalidURL.
    class _Validating:
        async def fetch(self, url, *, method="GET", body=None, headers=None, **kw):
            if re.search(r"[\x00-\x20\x7f]", url):
                raise http.client.InvalidURL("URL can't contain control characters")
            if method == "POST":
                return _R(200, "{}")
            return _R(200, '{"a":1,"b":2}')       # always compact → POST vectors never confirm

    res = await sspp.probe_sspp(_Validating(), "https://x.test/api")
    assert res["verdict"] == "no_sspp" and res["findings"] == []


# -- registration + dry_run -------------------------------------------------
@pytest.mark.asyncio
async def test_sspp_probe_tool_registered_and_dry_run(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "sspp_probe" in tools
    prev = await srv.sspp_probe(target="http://127.0.0.1/api", dry_run=True)   # dry_run bypasses the gate
    assert prev["dry_run"] is True
    assert any("json spaces" in p for p in prev["payloads"])
