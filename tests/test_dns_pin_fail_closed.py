"""Missing DNS vetting must not reopen the hostname connection fallback."""

import socket

import pytest

from moonmcp.net import http as httpmod
from moonmcp.net.http import HttpClient, HttpResult
from moonmcp.net.ratelimit import Governor
from moonmcp.scope import ScopeManager


def response(url, status=200, headers=None):
    return HttpResult(url=url, final_url=url, status=status, reason="",
                      headers=headers or [], body=b"fixture", elapsed_ms=0)


@pytest.fixture(params=["stdlib", "curl"])
def transport(request, monkeypatch):
    sent = []

    def send(url, method, headers, body, timeout, verify_tls, max_body, *extra):
        sent.append((url, extra[-1]))
        return response(url)

    monkeypatch.setattr(httpmod, "_USE_CURL_CFFI", request.param == "curl")
    monkeypatch.setattr(httpmod, "_IMPERSONATE_PROFILE", "synthetic-fixture")
    monkeypatch.setattr(httpmod, "_blocking_fetch", send)
    monkeypatch.setattr(httpmod, "_curl_cffi_fetch", send)
    return sent


@pytest.mark.parametrize("answers", [
    [], ["not-an-address"], [None], [1500000000], ["93.184.216.34", "not-an-address"],
    ["93.184.216.34", "127.0.0.1"],
])
async def test_unvetted_dns_never_dispatches(answers, transport):
    scope = ScopeManager(block_private=True, resolver=lambda _: answers)
    scope.add("example.test")
    client = HttpClient(Governor(rate=0, max_concurrency=1), user_agent="test",
                        connect_pin=scope.resolve_pin)
    result = await client.fetch("https://example.test/", scope_check=scope.is_in_scope)
    assert result.status is None and result.blocked_reason
    assert transport == []


@pytest.mark.parametrize("error", [socket.gaierror("NXDOMAIN"), OSError("resolver failed")])
async def test_system_dns_failure_never_dispatches(monkeypatch, error, transport):
    def resolve(*args, **kwargs):
        raise error

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    scope = ScopeManager(block_private=True)
    scope.add("example.test")
    client = HttpClient(Governor(rate=0, max_concurrency=1), user_agent="test",
                        connect_pin=scope.resolve_pin)
    result = await client.fetch("https://example.test/", scope_check=scope.is_in_scope)
    assert result.status is None and result.blocked_reason
    assert transport == []


async def test_successful_dns_is_resolved_once_and_its_address_is_dispatched(transport):
    lookups = []

    def resolve(host):
        lookups.append(host)
        return ["93.184.216.34"] if len(lookups) == 1 else ["127.0.0.1"]

    scope = ScopeManager(block_private=True, resolver=resolve)
    scope.add("example.test")
    client = HttpClient(Governor(rate=0, max_concurrency=1), user_agent="test",
                        connect_pin=scope.resolve_pin)
    result = await client.fetch("https://example.test/", scope_check=scope.is_in_scope)
    assert result.status == 200
    assert lookups == ["example.test"]
    assert transport == [("https://example.test/", "93.184.216.34")]


async def test_internal_testing_can_explicitly_disable_private_guard(transport):
    scope = ScopeManager(block_private=False, resolver=lambda _: pytest.fail("unexpected lookup"))
    scope.add("example.test")
    client = HttpClient(Governor(rate=0, max_concurrency=1), user_agent="test",
                        connect_pin=scope.resolve_pin)
    result = await client.fetch("https://example.test/", scope_check=scope.is_in_scope)
    assert result.status == 200
    assert transport == [("https://example.test/", None)]


async def test_unresolved_redirect_is_blocked_before_next_dispatch(monkeypatch, transport):
    scope = ScopeManager(block_private=True,
                         resolver=lambda host: ["93.184.216.34"] if host == "start.test" else [])
    scope.add("start.test")
    scope.add("next.test")

    def send(url, *args):
        transport.append(url)
        return response(url, 302, [("Location", "https://next.test/private")])

    monkeypatch.setattr(httpmod, "_blocking_fetch", send)
    monkeypatch.setattr(httpmod, "_curl_cffi_fetch", send)
    client = HttpClient(Governor(rate=0, max_concurrency=1), user_agent="test",
                        connect_pin=scope.resolve_pin)
    result = await client.fetch("https://start.test/", follow_redirects=True,
                                scope_check=scope.is_in_scope)
    assert transport == ["https://start.test/"]
    assert result.redirect_blocked == "https://next.test/private"
    assert result.blocked_reason


@pytest.mark.parametrize("target", ["", None, "http://["])
def test_invalid_pin_target_is_refused(target):
    scope = ScopeManager(block_private=True, resolver=lambda _: pytest.fail("unexpected lookup"))
    reason, pin = scope.resolve_pin(target)
    assert reason and pin is None
