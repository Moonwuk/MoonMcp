"""Server-side prototype pollution (SSPP) — safe reversible `json spaces` differential."""

import json

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


# -- registration + dry_run -------------------------------------------------
@pytest.mark.asyncio
async def test_sspp_probe_tool_registered_and_dry_run(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "sspp_probe" in tools
    prev = await srv.sspp_probe(target="http://127.0.0.1/api", dry_run=True)   # dry_run bypasses the gate
    assert prev["dry_run"] is True
    assert any("json spaces" in p for p in prev["payloads"])
