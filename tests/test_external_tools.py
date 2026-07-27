"""External-CLI registry (Kali integration): metadata integrity, category
grouping, and the intrusive gate on run_scanner.
"""

from dataclasses import replace

import pytest

from moonmcp import server as srv
from moonmcp.external import cli


def test_every_spec_is_well_formed():
    for name, spec in cli.KNOWN_TOOLS.items():
        assert spec.fallback, f"{name}: empty fallback"
        assert spec.description, f"{name}: empty description"
        assert spec.install, f"{name}: empty install hint"
        assert spec.category, f"{name}: empty category"
        assert isinstance(spec.intrusive, bool)


def test_registry_expanded_and_categorised():
    # The registry grew well beyond the original ProjectDiscovery core.
    assert len(cli.KNOWN_TOOLS) >= 25
    cats = {s.category for s in cli.KNOWN_TOOLS.values()}
    assert {"subdomain", "dns", "http", "content", "port", "vuln", "tls"} <= cats


def test_intrusive_classification():
    for t in ("nuclei", "nmap", "ffuf", "sqlmap", "masscan", "gobuster"):
        assert cli.is_intrusive(t), f"{t} should be intrusive"
    for t in ("subfinder", "httpx", "dnsx", "whatweb", "sslscan"):
        assert not cli.is_intrusive(t), f"{t} should not be intrusive"
    assert cli.is_intrusive("does-not-exist") is False


def test_tools_by_category_shape():
    grouped = cli.tools_by_category()
    assert "port" in grouped and "vuln" in grouped
    # Every entry carries the flags the agent needs.
    for items in grouped.values():
        for it in items:
            assert {"name", "available", "category", "intrusive", "native_fallback"} <= set(it)


def test_detect_tools_has_category_and_intrusive():
    meta = cli.detect_tools()["nuclei"]
    assert meta["category"] == "vuln"
    assert meta["intrusive"] is True
    assert meta["native_fallback"]


@pytest.mark.asyncio
async def test_external_tools_grouped_output():
    res = await srv.external_tools()
    assert res["known_count"] >= 25
    assert "by_category" in res and "port" in res["by_category"]
    assert isinstance(res["installed"], list)
    # Category filter narrows to one group.
    one = await srv.external_tools(category="tls")
    assert set(one["by_category"]) == {"tls"}


@pytest.mark.asyncio
async def test_run_scanner_intrusive_gate(fresh_context):
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.run_scanner(tool="nuclei", args=["-u", "https://127.0.0.1"])
    assert res["error"] == "disabled"
    assert "MOONMCP_ALLOW_INTRUSIVE" in res["detail"]


@pytest.mark.asyncio
async def test_run_scanner_non_intrusive_not_gated_by_intrusive(fresh_context):
    # httpx is not intrusive: with intrusive off it must NOT be blocked as disabled
    # (it will just report not-installed / run, but never "disabled").
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.run_scanner(tool="httpx", args=["-u", "https://127.0.0.1"])
    assert res.get("error") != "disabled"
