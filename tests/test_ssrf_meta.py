"""Response-based multi-cloud SSRF metadata probe + CN WAF signatures."""

import pytest

from moonmcp import server as srv
from moonmcp.web import ssrf_meta as sm
from moonmcp.web import waf


# -- pure injection / scan ---------------------------------------------------
def test_inject_param_get_puts_value_in_query():
    url, body = sm.inject_param("https://x.test/fetch?a=1", "url",
                                "http://169.254.169.254/latest/meta-data/", "GET")
    assert body is None
    assert "url=http%3A%2F%2F169.254.169.254" in url
    assert "a=1" in url  # existing params preserved


def test_inject_param_post_uses_body():
    url, body = sm.inject_param("https://x.test/fetch", "u", "http://x", "POST")
    assert url == "https://x.test/fetch"
    assert body is not None and b"u=http" in body


def test_scan_metadata_leak_case_insensitive():
    tgt = {"signatures": ["AccessKeyId", "SecretAccessKey"]}
    assert sm.scan_metadata_leak(tgt, '{"accesskeyid":"AK..","secretaccesskey":".."}')
    assert sm.scan_metadata_leak(tgt, "nothing here") == []


def test_metadata_targets_cover_the_major_clouds():
    providers = " ".join(t["provider"] for t in sm.CLOUD_METADATA_TARGETS)
    for cloud in ("AWS", "GCP", "Azure", "Alibaba", "Yandex", "Oracle", "DigitalOcean"):
        assert cloud in providers


def test_metadata_targets_include_kubernetes_api():
    k8s = [t for t in sm.CLOUD_METADATA_TARGETS if "Kubernetes" in t["provider"]]
    assert k8s, "k8s API-server SSRF targets must be present"
    assert any("kubernetes.default.svc" in t["url"] for t in k8s)
    # the /version target reflects gitVersion
    ver = next(t for t in k8s if t["url"].endswith("/version") and "svc" in t["url"])
    assert sm.scan_metadata_leak(ver, '{"major":"1","gitVersion":"v1.29.3","goVersion":"go1.21"}')


# -- end-to-end with a fake client -------------------------------------------
class _R:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def text(self, limit=None):
        return self._body


class _Client:
    def __init__(self, handler):
        self._handler = handler

    async def fetch(self, url, *, method="GET", body=None, headers=None, **kwargs):
        return self._handler(url, headers or {})


@pytest.mark.asyncio
async def test_probe_confirms_aws_metadata_leak():
    def handler(url, headers):
        # simulate a full-read SSRF that returns AWS IAM creds
        if "169.254.169.254%2Flatest%2Fmeta-data%2Fiam" in url:
            return _R(200, 'AccessKeyId: ASIA... SecretAccessKey: xyz security-credentials')
        return _R(200, "nothing")
    findings = await sm.probe_ssrf_metadata(_Client(handler), "https://x.test/fetch", "url")
    assert any(f["provider"].startswith("AWS") and f["verdict"] == "confirmed" for f in findings)


@pytest.mark.asyncio
async def test_probe_no_leak_returns_empty():
    findings = await sm.probe_ssrf_metadata(
        _Client(lambda url, h: _R(200, "totally benign page")), "https://x.test/fetch", "url")
    assert findings == []


@pytest.mark.asyncio
async def test_ssrf_metadata_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "ssrf_metadata_probe" in tools


# -- CN WAF signatures -------------------------------------------------------
def test_waf_detects_chinese_wafs():
    sig = waf._SIGNATURES
    assert any("SafeDog" in name for name in sig)
    assert any("BaoTa" in name or "宝塔" in name for name in sig)
    # SafeDog cookie signature is present and shaped correctly
    safedog = next(v for k, v in sig.items() if "SafeDog" in k)
    assert ("cookie", "safedog-flow-item") in safedog
