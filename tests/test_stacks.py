"""Regional stack fingerprint + deterministic unauth probes (CN/RU)."""

import hashlib

import pytest

from moonmcp import server as srv
from moonmcp.web import stacks


# -- passive fingerprint -----------------------------------------------------
def test_match_stack_signatures_body_and_cookie():
    got = stacks.match_stack_signatures(
        body="<script src='/bitrix/js/main.js'></script>", headers={}, set_cookies=[])
    assert "1C-Bitrix" in got
    got2 = stacks.match_stack_signatures(
        body="", headers={}, set_cookies=["rememberMe=xxxx; Path=/"])
    assert "Apache Shiro" in got2
    assert stacks.match_stack_signatures(body="nothing here", headers={}, set_cookies=[]) == []


# -- active probes via a fake client -----------------------------------------
class _R:
    def __init__(self, status, body="", headers=None, set_cookies=None):
        self.status = status
        self._body = body
        self._h = headers or {}
        self._sc = set_cookies or []

    def text(self, limit=None):
        return self._body

    def headers_map(self):
        return dict(self._h)

    def get_all(self, name):
        return self._sc if name.lower() == "set-cookie" else []


class _Client:
    def __init__(self, handler):
        self._handler = handler

    async def fetch(self, url, *, headers=None, **kwargs):
        return self._handler(url, headers or {})


@pytest.mark.asyncio
async def test_probe_thinkphp_confirmed_via_md5_echo():
    expected = hashlib.md5(b"moonmcp").hexdigest()  # noqa: S324

    def handler(url, headers):
        if "invokefunction" in url and "vars[1][]=moonmcp" in url:
            return _R(200, f"header {expected} footer")
        return _R(404, "")
    res = await stacks.probe_stack(_Client(handler), "https://t.test/")
    assert any(f["issue"] == "ThinkPHP invokefunction RCE" and f["verdict"] == "confirmed"
               for f in res.findings)


@pytest.mark.asyncio
async def test_probe_nacos_ua_bypass():
    def handler(url, headers):
        if "/nacos/v1/auth/users" in url:
            if headers.get("User-Agent") == "Nacos-Server":
                return _R(200, '{"totalCount":1,"pageItems":[{"username":"nacos"}]}')
            return _R(403, "forbidden")
        return _R(404, "")
    res = await stacks.probe_stack(_Client(handler), "https://t.test/")
    assert any("Nacos auth bypass" in f["issue"] for f in res.findings)


@pytest.mark.asyncio
async def test_probe_shiro_remember_me_tell():
    def handler(url, headers):
        if headers.get("Cookie") == "rememberMe=1":
            return _R(200, "", set_cookies=["rememberMe=deleteMe; Path=/; HttpOnly"])
        return _R(200, "")
    res = await stacks.probe_stack(_Client(handler), "https://t.test/")
    assert any(f["product"] == "Apache Shiro" for f in res.findings)


@pytest.mark.asyncio
async def test_probe_druid_and_clickhouse_exposure():
    def druid(url, headers):
        if url.endswith("/druid/index.html"):
            return _R(200, "<title>Druid Stat Index</title>")
        return _R(404, "")
    res = await stacks.probe_stack(_Client(druid), "https://t.test/")
    assert any(f["product"] == "Alibaba Druid" for f in res.findings)

    def ch(url, headers):
        if "query=SELECT%201" in url:
            return _R(200, "1")
        return _R(404, "")
    res2 = await stacks.probe_stack(_Client(ch), "https://t.test:8123/")
    assert any(f["product"] == "ClickHouse" and f["severity"] == "critical"
               for f in res2.findings)


@pytest.mark.asyncio
async def test_probe_druid_session_leak():
    def handler(url, headers):
        if url.endswith("/druid/index.html"):
            return _R(200, "<title>Druid Stat Index</title>")
        if url.endswith("/druid/websession.json"):
            return _R(200, '[{"SESSIONID":"abc123","Principal":"admin","LastAccessTime":"2026"}]')
        return _R(404, "")
    res = await stacks.probe_stack(_Client(handler), "https://t.test/")
    f = next(f for f in res.findings if f["product"] == "Alibaba Druid")
    assert f["severity"] == "high" and "session leak" in f["issue"].lower()


@pytest.mark.asyncio
async def test_probe_druid_monitor_only_stays_medium():
    def handler(url, headers):
        if url.endswith("/druid/index.html"):
            return _R(200, "druid-min.js")
        return _R(404, "")   # websession.json not exposed
    res = await stacks.probe_stack(_Client(handler), "https://t.test/")
    f = next(f for f in res.findings if f["product"] == "Alibaba Druid")
    assert f["severity"] == "medium"


@pytest.mark.asyncio
async def test_probe_vector_stores():
    def chroma(url, headers):
        if url.endswith("/api/v2/heartbeat"):
            return _R(200, '{"nanosecond heartbeat": 1720000000000000000}')
        if url.endswith("/api/v2/version"):
            return _R(200, '"1.0.3"')
        return _R(404, "")
    res = await stacks.probe_stack(_Client(chroma), "https://t.test:8000/")
    f = next(f for f in res.findings if f["product"] == "ChromaDB")
    assert f["severity"] == "critical" and "CVE-2026-45829" in f["detail"] and "1.0.3" in f["detail"]

    def weaviate(url, headers):
        if url.endswith("/v1/meta"):
            return _R(200, '{"hostname":"http://[::]:8080","version":"1.24.1","modules":{}}')
        return _R(404, "")
    res2 = await stacks.probe_stack(_Client(weaviate), "https://t.test:8080/")
    assert any(f["product"] == "Weaviate" and f["verdict"] == "exposed" for f in res2.findings)

    def qdrant(url, headers):
        if url.endswith("/collections"):
            return _R(200, '{"result":{"collections":[{"name":"docs"}]},"status":"ok","time":0.0}')
        return _R(404, "")
    res3 = await stacks.probe_stack(_Client(qdrant), "https://t.test:6333/")
    assert any(f["product"] == "Qdrant" and f["severity"] == "high" for f in res3.findings)


@pytest.mark.asyncio
async def test_probe_stack_clean_target_no_findings():
    res = await stacks.probe_stack(_Client(lambda url, h: _R(404, "not found")), "https://t.test/")
    assert res.findings == []


@pytest.mark.asyncio
async def test_stack_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "stack_probe" in tools
