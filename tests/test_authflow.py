"""Account-takeover flow abuses: in-band secret leak + reset poisoning."""

import pytest

from moonmcp import server as srv
from moonmcp.web import authflow as af


# -- scan_response_leak (pure) ----------------------------------------------
def test_scan_flags_named_otp_and_reset_token_fields():
    body = '{"status":"sent","otp":"483920","reset_token":"abcdef123456"}'
    kinds = {f["kind"] for f in af.scan_response_leak(body)}
    assert kinds == {"secret_in_body"}
    fields = {f["field"].lower() for f in af.scan_response_leak(body)}
    assert "otp" in fields and any("reset" in f for f in fields)


def test_scan_flags_reset_link_in_body():
    body = '{"message":"check email","link":"https://acme.test/reset-password?token=xyz789abc"}'
    res = af.scan_response_leak(body)
    assert any(f["kind"] == "reset_link_in_body" for f in res)


def test_scan_flags_bare_code_only_with_otp_context():
    with_ctx = af.scan_response_leak('{"message":"Your one-time code is 991234"}')
    assert any(f["kind"] == "otp_code_in_body" and f["verdict"] == "review" for f in with_ctx)
    # a bare number with no OTP wording is not flagged (avoids order-id noise)
    assert af.scan_response_leak('{"order_id":991234,"total":4200}') == []


def test_scan_ignores_csrf_oauth_and_null_values():
    assert af.scan_response_leak('{"csrf_token":"a1b2c3d4e5"}') == []
    assert af.scan_response_leak('{"access_token":"ya29.longtokenvalue"}') == []
    assert af.scan_response_leak('{"otp":null,"reset_token":"sent"}') == []


def test_secrets_are_redacted():
    res = af.scan_response_leak('{"otp":"483920"}')
    sample = res[0]["sample"]
    assert sample != "483920" and "*" in sample


# -- assess_reflection (pure) -----------------------------------------------
def test_assess_reflection_body_and_location():
    assert af.assess_reflection("link https://evil.test/x", "", "evil.test") is True
    assert af.assess_reflection("", "https://EVIL.test/reset", "evil.test") is True
    assert af.assess_reflection("nothing here", "https://acme.test/", "evil.test") is False


# -- probes via fake clients ------------------------------------------------
class _Resp:
    def __init__(self, status=200, body="", location=""):
        self.status = status
        self._body = body
        self._location = location

    def text(self, limit=None):
        return self._body if limit is None else self._body[:limit]

    def header(self, name, default=None):
        return self._location or default if name.lower() == "location" else default


class _LeakClient:
    async def fetch(self, url, **kwargs):
        return _Resp(200, '{"otp":"771122","status":"sent"}')


class _PoisonClient:
    """Reflects the canary in Location only when *reflect_header* is present."""

    def __init__(self, reflect_header):
        self._h = reflect_header.lower()

    async def fetch(self, url, *, method="GET", body=None, headers=None, **kwargs):
        headers = headers or {}
        val = next((v for k, v in headers.items() if k.lower() == self._h), None)
        if val:
            host = val.split("host=", 1)[-1]
            return _Resp(200, "reset queued", location=f"https://{host}/reset?token=abc")
        return _Resp(200, "ok")


@pytest.mark.asyncio
async def test_probe_response_leak_finds_in_band_otp():
    res = await af.probe_response_leak(_LeakClient(), "https://x.test/api/reset")
    assert any(f["kind"] == "secret_in_body" for f in res)


@pytest.mark.asyncio
async def test_probe_reset_poison_flags_reflected_header():
    res = await af.probe_reset_poison(
        _PoisonClient("x-forwarded-host"), "https://x.test/reset", "evil.attacker.test")
    assert any(f["header"] == "X-Forwarded-Host" and f["where"] == "location" for f in res)


@pytest.mark.asyncio
async def test_probe_reset_poison_covers_forwarded_syntax():
    # the Forwarded header uses `host=<canary>` syntax — must still be detected
    res = await af.probe_reset_poison(
        _PoisonClient("forwarded"), "https://x.test/reset", "evil.attacker.test")
    assert any(f["header"] == "Forwarded" for f in res)


@pytest.mark.asyncio
async def test_probe_reset_poison_no_reflection_no_finding():
    res = await af.probe_reset_poison(
        _PoisonClient("x-never-sent"), "https://x.test/reset", "evil.attacker.test")
    assert res == []


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_authflow_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert {"response_leak_probe", "reset_poison_probe"} <= tools


def test_scan_bare_code_needs_otp_context_nearby_not_anywhere():
    # OTP wording present but FAR (>60 chars) from a bare order id → not flagged
    # (the old "context anywhere in body" check false-positived on this).
    far = '{"order_id":887766,"note":"' + "x" * 90 + '","help":"set up your 2fa code"}'
    assert af.scan_response_leak(far) == []
    # a bare code right next to the OTP wording is still flagged.
    near = '{"msg":"Your verification code is 445566, it expires soon"}'
    assert any(f["kind"] == "otp_code_in_body" for f in af.scan_response_leak(near))
