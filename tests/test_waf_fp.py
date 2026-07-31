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
        if "q=" in url and ("script" in url or "OR" in url or "passwd" in url):  # the active WAF probe carries attack payload in q=
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


class _BlocksEverythingClient:
    """Auth-walled / down host: 403 to EVERY request, benign or not."""

    async def fetch(self, url, **kwargs):
        return _res(403, b"403 Forbidden")


@pytest.mark.asyncio
async def test_blocks_everything_host_is_ambiguous_not_confident_waf():
    # The benign baseline is already 403, so the attack getting 403 is NOT attack-specific.
    # It must NOT be asserted as a confident WAF (that's the FP) — but it must NOT be silently
    # dropped either (a WAF challenging ALL traffic, e.g. Cloudflare under-attack, looks like
    # this — dropping it is the FN the review caught). Surface it as a low-confidence lead.
    res = await waf.detect_waf(_BlocksEverythingClient(), "https://t.example", active=True)
    assert "Unknown WAF (request blocked)" not in res.detected     # no over-claim
    assert any("Possible WAF" in d for d in res.detected)          # but not hidden either


class _NotAcceptableClient:
    """A benign page whose body merely contains the phrase 'not acceptable'."""

    async def fetch(self, url, **kwargs):
        return _res(200, b"<html><p>This behaviour is not acceptable in our community.</p></html>")


@pytest.mark.asyncio
async def test_passive_not_acceptable_prose_is_not_modsecurity():
    # The passive body scan must not fingerprint a benign 'not acceptable' page as
    # ModSecurity (the generic body signature was removed).
    res = await waf.detect_waf(_NotAcceptableClient(), "https://t.example", active=False)
    assert "ModSecurity" not in res.detected


def test_waf_bypass_double_encode_is_a_real_transform():
    # the double-encode transform must actually double-encode (%3C -> %253C), not be a
    # silent no-op that _send collapses back to single-encoding.
    from urllib.parse import quote

    from moonmcp.web import waf_bypass as wb
    payload = "<script>x</script>"
    out = wb._TRANSFORMS["double-encode"](payload)
    # after _send re-encodes with safe='%', the '%25' sequences survive intact
    sent = quote(out, safe="%")
    assert "%253C" in sent and "%3C" not in sent.replace("%253C", "")
