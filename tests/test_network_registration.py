"""Network family extraction must retain context, scope and dispatch policy."""

import functools
from types import SimpleNamespace

import pytest

from moonmcp import sdk, server
from moonmcp.families import network
from moonmcp.net.http import HttpResult
from moonmcp.outcomes import safe_tool
from moonmcp.registry import policy


async def test_network_registrations_bind_independent_clients_and_gates():
    applications = []
    seen = []

    for index in (0, 1):
        async def fetch(url, *, index=index, **kwargs):
            assert kwargs["scope_check"](url)
            seen.append((index, url))
            return HttpResult(url, url, 200 + index, "OK", [], b"", 0)

        def gate_factory(*, index=index):
            def decorate(fn):
                @functools.wraps(fn)
                async def gated(*args, **kwargs):
                    target = kwargs.get("target", args[0] if args else "")
                    if not target.startswith(f"https://context{index}.test"):
                        return {"error": "out_of_scope"}
                    return await fn(*args, **kwargs)
                return safe_tool(gated)
            return decorate

        ctx = SimpleNamespace(http=SimpleNamespace(fetch=fetch),
                              settings=SimpleNamespace(max_redirects=3))
        app = sdk.MoonMCPFastMCP(f"context-{index}")
        network.register(app, gate_factory, lambda ctx=ctx: ctx,
                         lambda index=index: lambda url: url.startswith(f"https://context{index}.test"),
                         server._split_host_port)
        applications.append(app)

    for index, app in enumerate(applications):
        success = await app.call_tool("http_probe", {"target": f"https://context{index}.test/"})
        assert success.structuredContent["status"] == 200 + index
        denied = await app.call_tool("http_probe", {"target": f"https://context{1-index}.test/"})
        assert denied.structuredContent["error"] == "out_of_scope"
    assert seen == [(0, "https://context0.test/"), (1, "https://context1.test/")]


@pytest.mark.parametrize("name,arguments", [
    ("http_probe", {"target": "https://not-authorised.test"}),
    ("enumerate_subdomains", {"domain": "not-authorised.test"}),
    ("edge_map", {"target": "https://not-authorised.test"}),
    ("ratelimit_probe", {"target": "https://not-authorised.test"}),
])
async def test_extracted_live_tools_reject_targets_before_transport(name, arguments, fresh_context,
                                                                  monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("scope denial must precede any network request")

    monkeypatch.setattr(fresh_context.http, "fetch", forbidden)
    result = await server.mcp.call_tool(name, arguments)
    assert result.isError
    assert result.structuredContent["error"] == "out_of_scope"
    assert sdk.get_registered(server.mcp, name).fn.__module__.startswith("moonmcp.families.")


def test_extraction_does_not_expand_managed_transport_allowlist():
    for name in ("dns_lookup", "tls_inspect", "http_behavior", "fingerprint"):
        assert policy(name).accounting == "unmetered"
    assert policy("http_probe").accounting == "http_client"
