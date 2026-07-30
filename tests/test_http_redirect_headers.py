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

    def fake_fetch(url, method, merged, body, timeout, verify_tls, max_body):
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
