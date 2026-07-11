"""detect_waf must catch WAFs that block with a 200/503 body page, not just 4xx."""

import pytest

from moonmcp.net.http import HttpResult
from moonmcp.web import waf


def _res(status, body=b"", url="https://t.example"):
    return HttpResult(url=url, final_url=url, status=status, reason="", headers=[],
                      body=body, elapsed_ms=1.0)


class _BlockPageClient:
    """Benign baseline; the active attack probe gets a 200 WAF block page."""

    async def fetch(self, url, **kwargs):
        if "moon=" in url:  # the active WAF probe carries our marker param
            return _res(200, b"Access Denied - Ray ID: abc123. Request blocked by security policy.")
        return _res(200, b"welcome home")


class _CleanClient:
    async def fetch(self, url, **kwargs):
        return _res(200, b"welcome home")


@pytest.mark.asyncio
async def test_detect_waf_catches_200_block_page():
    res = await waf.detect_waf(_BlockPageClient(), "https://t.example", active=True)
    assert res.blocked_probe is True and res.block_status == 200
    assert any("Unknown WAF" in d for d in res.detected)


@pytest.mark.asyncio
async def test_detect_waf_no_false_block_on_clean_200():
    res = await waf.detect_waf(_CleanClient(), "https://t.example", active=True)
    assert res.blocked_probe is False and res.detected == []
