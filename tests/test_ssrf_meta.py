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
    findings = await sm.probe_ssrf_metadata(_Client(handler), "https://x.test/fetch", "url", confirm_creds=True)
    assert any(f["provider"].startswith("AWS") and f["verdict"] == "confirmed" for f in findings)


@pytest.mark.asyncio
async def test_probe_no_leak_returns_empty():
    # confirm_creds=True so the credential probes actually run (not just the
    # dry_run note); a benign page yields no credential signatures.
    findings = await sm.probe_ssrf_metadata(
        _Client(lambda url, h: _R(200, "totally benign page")), "https://x.test/fetch", "url",
        confirm_creds=True)
    # No critical findings on a benign page (the dry_run note is only added when
    # confirm_creds=False, so here findings should be empty).
    assert findings == []


@pytest.mark.asyncio
async def test_probe_default_mode_benign_has_no_confirmed_finding():
    # Default mode always appends the informational dry_run note, so `findings` is
    # never empty — but on a benign target NONE is verdict="confirmed". The tool must
    # key `vulnerable` off confirmed leaks, not bool(findings).
    findings = await sm.probe_ssrf_metadata(
        _Client(lambda url, h: _R(200, "totally benign page")), "https://x.test/fetch", "url")
    assert findings  # the dry_run note is present
    assert not any(f.get("verdict") == "confirmed" for f in findings)


@pytest.mark.asyncio
async def test_ssrf_metadata_tool_not_vulnerable_on_benign(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=True)
    res = await srv.ssrf_metadata_probe(target=f"{base}/echo", param="url")
    assert res["vulnerable"] is False, res            # regression: was always True
    assert "no metadata credential signatures" in res["note"]


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
