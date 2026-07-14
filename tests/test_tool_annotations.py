"""MCP tool annotations derived from the @active_tool / @safe_tool scope markers."""

import pytest

from moonmcp import server as srv


async def _by_name():
    return {t.name: t for t in await srv.mcp.list_tools()}


@pytest.mark.asyncio
async def test_every_tool_has_annotations(fresh_context):
    tools = await srv.mcp.list_tools()
    assert tools  # sanity
    missing = [t.name for t in tools if t.annotations is None]
    assert missing == [], f"tools without annotations: {missing}"


@pytest.mark.asyncio
async def test_intrusive_probe_is_destructive_not_readonly(fresh_context):
    by = await _by_name()
    for name in ("sqli_probe", "cmdi_probe", "saml_xsw_probe"):
        a = by[name].annotations
        assert a.readOnlyHint is False, name
        assert a.destructiveHint is True, name
        assert a.openWorldHint is True, name


@pytest.mark.asyncio
async def test_non_intrusive_active_tool_is_readonly_openworld(fresh_context):
    by = await _by_name()
    for name in ("fingerprint", "crawl"):
        a = by[name].annotations
        assert a.readOnlyHint is True, name
        assert a.destructiveHint is not True, name   # not a destructive tool
        assert a.openWorldHint is True, name          # but it does touch the target


@pytest.mark.asyncio
async def test_safe_offline_tool_is_readonly(fresh_context):
    by = await _by_name()
    for name in ("jwt_analyze", "deserialize_fingerprint", "tool_catalog"):
        a = by[name].annotations
        assert a.readOnlyHint is True, name
        assert a.destructiveHint is not True, name


@pytest.mark.asyncio
async def test_annotations_track_the_scope_markers(fresh_context):
    # The annotation must agree with the underlying @active_tool markers for every
    # tool — this is the invariant that keeps the hint honest as tools are added.
    by = await _by_name()
    for name, tool in srv.mcp._tool_manager._tools.items():
        gated = getattr(tool.fn, "__moonmcp_gated__", False)
        intrusive = getattr(tool.fn, "__moonmcp_intrusive__", False)
        a = by[name].annotations
        if gated and intrusive:
            assert a.readOnlyHint is False and a.destructiveHint is True, name
        elif gated:
            assert a.readOnlyHint is True and a.openWorldHint is True, name
        else:
            assert a.readOnlyHint is True, name
