"""Integration tests driving the MCP tool functions against a local server."""


import pytest

from moonmcp import server as srv


@pytest.mark.asyncio
async def test_tool_inventory():
    tools = await srv.mcp.list_tools()
    names = {t.name for t in tools}
    expected = {
        "server_status", "scope_list", "scope_add", "scope_exclude", "scope_remove",
        "enumerate_subdomains", "wayback_urls", "cve_lookup", "cve_search", "host_intel",
        "dns_lookup", "http_probe", "tls_inspect", "analyze_headers", "fingerprint",
        "well_known", "port_scan", "content_discovery", "recon_target",
        "external_tools", "run_scanner", "vuln_scan",
    }
    assert expected <= names
    # Every tool must carry a description (it is what the model reads).
    for t in tools:
        assert t.description and len(t.description) > 20


@pytest.mark.asyncio
async def test_http_probe_local(local_server, fresh_context):
    base, _ = local_server
    res = await srv.http_probe(target=base)
    assert res["status"] == 200
    assert res["title"] == "Local"
    assert res["headers"]["Server"] == "nginx/1.25.1"


@pytest.mark.asyncio
async def test_analyze_headers_local(local_server, fresh_context):
    base, _ = local_server
    res = await srv.analyze_headers(target=base)
    assert res["grade"] == "F"  # no security headers set
    assert any(leak["header"] == "server" for leak in res.get("info_leaks", []))


@pytest.mark.asyncio
async def test_fingerprint_local(local_server, fresh_context):
    base, _ = local_server
    res = await srv.fingerprint(target=base)
    names = {t["name"] for t in res.get("technologies", [])}
    assert "nginx" in names
    assert "Express" in names


@pytest.mark.asyncio
async def test_well_known_local(local_server, fresh_context):
    base, _ = local_server
    res = await srv.well_known(target=base)
    assert "robots.txt" in res.get("files", {})
    assert "/admin" in res.get("robots_paths", [])


@pytest.mark.asyncio
async def test_port_scan_local(local_server, fresh_context):
    _, port = local_server
    res = await srv.port_scan(target="127.0.0.1", ports=f"{port},1,2")
    open_ports = {p["port"] for p in res.get("open_ports", [])}
    assert port in open_ports


@pytest.mark.asyncio
async def test_scope_guard_blocks_out_of_scope(fresh_context):
    res = await srv.http_probe(target="https://definitely-not-in-scope.example")
    assert res["error"] == "out_of_scope"


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_is_blocked(local_server, fresh_context):
    base, _ = local_server
    res = await srv.http_probe(target=f"{base}/redirect-out")
    # We received the 302 but must NOT have followed it off-scope.
    assert res["status"] == 302
    assert res.get("redirect_blocked", "").startswith("http://evil.example")
    assert "evil.example" not in (res.get("final_url") or "")


@pytest.mark.asyncio
async def test_run_scanner_scope_checks_args(fresh_context):
    # Host lives in args, not in `target`; must still be scope-checked.
    res = await srv.run_scanner(tool="httpx", args=["-u", "https://out-of-scope.example"])
    assert res["error"] == "out_of_scope"


@pytest.mark.asyncio
async def test_run_scanner_requires_target_when_enforced(fresh_context):
    res = await srv.run_scanner(tool="nuclei", args=["-version"])
    assert res["error"] == "no_target"


@pytest.mark.asyncio
async def test_intrusive_gate(fresh_context):
    # Disable intrusive tools; port_scan must refuse even for an in-scope host.
    from dataclasses import replace

    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.port_scan(target="127.0.0.1", ports="80")
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_scope_management_tools():
    # These do not require network; verify the flow end to end.
    from moonmcp.context import build_context

    ctx = build_context()
    srv._CTX = ctx
    add = await srv.scope_add(target="example.org")
    assert "example.org" in add["scope"]["in_scope"]
    excl = await srv.scope_exclude(target="secret.example.org")
    assert "secret.example.org" in excl["scope"]["out_of_scope"]
    listing = await srv.scope_list()
    assert listing["enforced"] in (True, False)
    rem = await srv.scope_remove(target="example.org")
    assert rem["removed"] is True
    srv._CTX = None  # reset global for other tests
