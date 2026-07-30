"""A cross-origin redirect must drop ALL non-allowlisted headers.

The old code dropped only a hardcoded {authorization, cookie, proxy-authorization}
set plus engagement-auth keys, so a caller-supplied custom credential header
(X-Api-Key, X-Auth-Token, a custom bearer) leaked to the redirect target.
"""

import pytest

from moonmcp.net import http as httpmod
from moonmcp.net.http import HttpClient, HttpResult
from moonmcp.net.ratelimit import Governor


def _res(url, status, headers=None):
    return HttpResult(url=url, final_url=url, status=status, reason="",
                      headers=headers or [], body=b"", elapsed_ms=1.0)


def _install(monkeypatch, redirect_to):
    captured = []

    def fake_fetch(url, method, merged, body, timeout, verify_tls, max_body, pinned_ip=None):
        captured.append((url, dict(merged)))
        if url.endswith("/start"):
            return _res(url, 302, [("Location", redirect_to)])
        return _res(url, 200)

    monkeypatch.setattr(httpmod, "_USE_CURL_CFFI", False)
    monkeypatch.setattr(httpmod, "_blocking_fetch", fake_fetch)
    return captured


@pytest.mark.asyncio
async def test_cross_origin_redirect_drops_all_custom_auth_headers(monkeypatch):
    captured = _install(monkeypatch, "https://evil.example/next")
    client = HttpClient(Governor(rate=100, max_concurrency=4), user_agent="UA/1.0")
    await client.fetch(
        "https://a.example/start",
        headers={"Authorization": "Bearer secret", "X-Api-Key": "k-123",
                 "X-Auth-Token": "t-456", "Cookie": "s=1"},
        follow_redirects=True,
    )
    assert len(captured) == 2, captured
    first = {k.lower(): v for k, v in captured[0][1].items()}
    second = {k.lower(): v for k, v in captured[1][1].items()}
    # the first (same-origin) hop carried the caller credentials
    assert first.get("x-api-key") == "k-123"
    # the cross-origin hop dropped EVERY credential header, including the custom ones
    for leaked in ("authorization", "cookie", "x-api-key", "x-auth-token"):
        assert leaked not in second, f"{leaked} leaked cross-origin"
    # safe, non-identifying headers still cross
    assert second.get("user-agent") == "UA/1.0"


@pytest.mark.asyncio
async def test_same_origin_redirect_keeps_custom_headers(monkeypatch):
    captured = _install(monkeypatch, "https://a.example/next")
    client = HttpClient(Governor(rate=100, max_concurrency=4), user_agent="UA/1.0")
    await client.fetch("https://a.example/start",
                       headers={"X-Api-Key": "k-123"}, follow_redirects=True)
    second = {k.lower(): v for k, v in captured[1][1].items()}
    assert second.get("x-api-key") == "k-123"   # same origin: header is preserved


@pytest.mark.asyncio
async def test_fetch_pins_the_vetted_ip_for_the_connection(monkeypatch):
    # the connect guard resolves+vets an IP; the transport must dial THAT IP, not
    # re-resolve the hostname (DNS-rebinding TOCTOU defence).
    seen = {}

    def fake_fetch(url, method, merged, body, timeout, verify_tls, max_body, pinned_ip=None):
        seen["pinned_ip"] = pinned_ip
        return _res(url, 200)

    monkeypatch.setattr(httpmod, "_USE_CURL_CFFI", False)
    monkeypatch.setattr(httpmod, "_blocking_fetch", fake_fetch)
    client = HttpClient(Governor(rate=100, max_concurrency=4), user_agent="UA/1.0",
                        connect_pin=lambda host: (None, "203.0.113.7"))
    await client.fetch("https://target.example/x")
    assert seen["pinned_ip"] == "203.0.113.7"


@pytest.mark.asyncio
async def test_fetch_blocks_when_connect_pin_reports_private(monkeypatch):
    def fake_fetch(*a, **k):
        raise AssertionError("must not connect when the guard blocks the host")

    monkeypatch.setattr(httpmod, "_USE_CURL_CFFI", False)
    monkeypatch.setattr(httpmod, "_blocking_fetch", fake_fetch)
    client = HttpClient(Governor(rate=100, max_concurrency=4), user_agent="UA/1.0",
                        connect_pin=lambda host: ("blocked: private/reserved", None))
    res = await client.fetch("https://rebind.example/x")
    assert res.status is None
    assert res.blocked_reason == "blocked: private/reserved"


def test_read_capped_bounds_body_and_stops_early():
    # a peer that streams forever must not blow up memory: _read_capped stops the
    # moment it passes the cap and returns exactly `limit` bytes, truncated=True.
    from moonmcp.net.http import _read_capped

    def forever():
        while True:
            yield b"x" * 1000

    body, truncated = _read_capped(forever(), 4096)
    assert truncated is True and len(body) == 4096
    # under / exactly-at / just-over the limit
    assert _read_capped([b"abc", b"de"], 100) == (b"abcde", False)
    assert _read_capped([b"a" * 100], 100) == (b"a" * 100, False)   # exactly limit → not truncated
    assert _read_capped([b"a" * 101], 100) == (b"a" * 100, True)
    assert _read_capped([b"", b"ab", b""], 100) == (b"ab", False)   # empty chunks skipped
