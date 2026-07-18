"""Spring Boot Actuator + Jolokia exploitation-recon."""

import json
from urllib.parse import urlsplit

import pytest

from moonmcp import server as srv
from moonmcp.web import actuator as ac


# -- pure analysers ---------------------------------------------------------
def test_secret_name_and_mask():
    assert ac.is_secret_name("spring.datasource.password")
    assert ac.is_secret_name("app.jwt.secret") and ac.is_secret_name("AWS_SECRET_ACCESS_KEY")
    assert not ac.is_secret_name("server.port")
    assert ac.is_masked("******") and ac.is_masked("") and ac.is_masked(None) and ac.is_masked("null")
    assert not ac.is_masked("s3cr3t!") and not ac.is_masked(12345)   # str / numeric = real leak
    # a boolean is a config flag (*-enabled / *-required), never a credential → not a leak
    assert ac.is_masked(True) and ac.is_masked(False)


def test_leaked_secrets_boot2_and_masked():
    env = {"propertySources": [{"name": "systemEnvironment", "properties": {
        "spring.datasource.password": {"value": "pg-pass-123"},
        "management.security.secret": {"value": "******"},          # masked → not a leak
        "server.port": {"value": "8080"}}}]}
    leaks = ac.leaked_secrets(env)
    assert [x["property"] for x in leaks] == ["spring.datasource.password"]
    assert leaks[0]["value_preview"] == "pg-pass-123"


def test_leaked_secrets_ignores_boolean_flags():
    # secret-NAMED but boolean-VALUED config flags must not be reported as credential leaks
    env = {"propertySources": [{"name": "applicationConfig", "properties": {
        "app.security.encryption-enabled": {"value": True},
        "oauth.client-secret-required": {"value": False},
        "spring.datasource.password": {"value": "real-leak"}}}]}
    assert [x["property"] for x in ac.leaked_secrets(env)] == ["spring.datasource.password"]


def test_leaked_secrets_boot1_flat():
    env = {"profiles": [], "applicationConfig: [classpath:/app.yml]": {
        "spring.mail.password": "hunter2", "server.port": 8080}}
    assert [x["property"] for x in ac.leaked_secrets(env)] == ["spring.mail.password"]


def test_is_heapdump():
    assert ac.is_heapdump(b"JAVA PROFILE 1.0.2\x00\x01\x02")
    assert not ac.is_heapdump(b"<html>404") and not ac.is_heapdump(b"")


def test_jolokia_agent_and_mbeans():
    assert ac.jolokia_agent('{"value":{"agent":"1.6.2","protocol":"7.2"},"status":200}') == "1.6.2"
    assert ac.jolokia_agent("<html>") is None and ac.jolokia_agent('{"value":{}}') is None
    assert "getmbeansfromurl" in ac.dangerous_mbeans('{"x":"type=MLet","op":"getMBeansFromURL"}')
    assert ac.dangerous_mbeans('{"safe":"type=Memory"}') == []


# -- probe against fake apps ------------------------------------------------
class _R:
    def __init__(self, status, text=None, body=b""):
        self.status = status
        self.body = text.encode() if text is not None else body

    def text(self, limit=None):
        return self.body.decode("latin-1", "replace")


class _VulnBoot2:
    async def fetch(self, url, *, method="GET", headers=None, max_body=None, timeout=None,
                    scope_check=None, follow_redirects=False, **kw):
        p = urlsplit(url).path
        if p == "/actuator":
            return _R(200, '{"_links":{"self":{"href":"/actuator"},"env":{"href":"/actuator/env"}}}')
        if p == "/actuator/env":
            return _R(200, json.dumps({"propertySources": [{"name": "systemEnvironment", "properties": {
                "spring.datasource.password": {"value": "s3cr3t!"},
                "server.port": {"value": "8080"}}}]}))
        if p == "/actuator/heapdump":
            return _R(206, body=b"JAVA PROFILE 1.0.2\x00" + b"\x00" * 40)
        if p == "/actuator/mappings":
            return _R(200, '{"mappings":{"dispatcherServlet":[]}}')
        if p == "/actuator/jolokia/version":
            return _R(200, '{"value":{"agent":"1.6.2","protocol":"7.2"},"status":200}')
        if p == "/actuator/jolokia/list":
            return _R(200, '{"value":{"JMImplementation":{"type=MLet":{"op":{"getMBeansFromURL":{}}}}}}')
        return _R(404, "not found")


class _VulnBoot1:
    async def fetch(self, url, *, method="GET", headers=None, max_body=None, timeout=None,
                    scope_check=None, follow_redirects=False, **kw):
        p = urlsplit(url).path
        if p == "/env":
            return _R(200, json.dumps({"profiles": [], "applicationConfig: [classpath:/app.yml]": {
                "spring.datasource.password": "pg-pass-123", "server.port": 8080}}))
        return _R(404, "nope")


class _MaskedOnly:
    async def fetch(self, url, *, method="GET", headers=None, **kw):
        p = urlsplit(url).path
        if p == "/actuator":
            return _R(200, '{"_links":{"env":{}}}')
        if p == "/actuator/env":
            return _R(200, json.dumps({"propertySources": [{"name": "s", "properties": {
                "spring.datasource.password": {"value": "******"}}}]}))
        return _R(404, "x")


class _NotActuator:
    async def fetch(self, url, *, method="GET", headers=None, **kw):
        return _R(404, "<html>not found</html>")


@pytest.mark.asyncio
async def test_probe_boot2_full_loot():
    res = await ac.probe_actuator(_VulnBoot2(), "https://x.test")
    assert res["actuator_base"] == "/actuator" and res["verdict"] == "confirmed"
    by = {f["kind"]: f for f in res["findings"]}
    assert by["actuator_env_secret"]["property"] == "spring.datasource.password"
    assert by["actuator_heapdump"]["severity"] == "critical"
    assert by["actuator_mappings"]["severity"] == "low"
    assert by["jolokia"]["agent"] == "1.6.2" and by["jolokia"]["rce_mbeans"]


@pytest.mark.asyncio
async def test_probe_boot1_env_secret():
    res = await ac.probe_actuator(_VulnBoot1(), "https://x.test")
    assert res["actuator_base"] == "" and res["verdict"] == "confirmed"
    assert any(f["kind"] == "actuator_env_secret" for f in res["findings"])


@pytest.mark.asyncio
async def test_probe_masked_env_no_leak():
    res = await ac.probe_actuator(_MaskedOnly(), "https://x.test")
    assert not any(f["kind"] == "actuator_env_secret" for f in res["findings"])


@pytest.mark.asyncio
async def test_probe_not_actuator():
    res = await ac.probe_actuator(_NotActuator(), "https://x.test")
    assert res["actuator_base"] is None and res["verdict"] == "not_actuator" and res["findings"] == []


@pytest.mark.asyncio
async def test_actuator_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "actuator_probe" in tools
