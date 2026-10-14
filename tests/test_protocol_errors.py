"""Protocol errors must be machine-readable without changing Python payloads."""

import asyncio
import json
import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import CallToolResult

from moonmcp import server
from moonmcp.__main__ import main
from moonmcp.outcomes import MoonMCPFastMCP, failure


def test_execution_error_classification_ignores_negative_verdicts():
    assert failure({"verdict": "unconfirmed", "confirmed": False}) is None
    assert failure({"success": False, "observations": [{"error": "endpoint unavailable"}]}) is None
    assert failure({"available": False}) is None
    assert failure({"error": None}) is None
    assert failure({"error": "invalid_input", "detail": "budget exceeded: requests"}).code == "budget_exhausted"
    assert failure({"error": "timeout"}).retryable
    assert not failure({"error": "invalid_input"}).retryable


async def test_adapter_preserves_payload_and_negative_verdict():
    mcp = MoonMCPFastMCP("test")

    @mcp.tool()
    async def bad() -> dict:
        return {"error": "invalid_input", "detail": "wrong argument"}

    @mcp.tool()
    async def negative() -> dict:
        return {"verdict": "unconfirmed", "signals": []}

    original = await bad()
    assert isinstance(original, dict)
    result = await mcp.call_tool("bad", {})
    assert isinstance(result, CallToolResult) and result.isError
    assert result.structuredContent == original
    assert json.loads(result.content[0].text) == original
    assert result.meta["moonmcp.outcome"]["code"] == "invalid_input"
    negative_result = await mcp.call_tool("negative", {})
    assert not negative_result.isError
    assert negative_result.structuredContent == await negative()


async def test_compact_filter_keeps_hidden_tool_out_of_direct_protocol():
    mcp = MoonMCPFastMCP("test")

    @mcp.tool()
    async def direct() -> dict:
        return {"ok": True}

    @mcp.tool()
    async def facade() -> dict:
        return {"ok": True}

    mcp.advertised_tools = {"facade"}
    assert [t.name for t in await mcp.list_tools()] == ["facade"]
    with pytest.raises(ToolError, match="not advertised"):
        await mcp.call_tool("direct", {})
    assert mcp._tool_manager.get_tool("direct") is not None
    assert not (await mcp.call_tool("facade", {})).isError


def test_cli_application_failure_is_nonzero_and_keeps_json(capsys, monkeypatch, tmp_path):
    from moonmcp.config import Settings
    from moonmcp.context import build_context

    monkeypatch.setenv("MOONMCP_STATE_DIR", str(tmp_path))
    context = build_context(Settings(state_dir=str(tmp_path)))
    monkeypatch.setattr(server, "_CTX", context)
    try:
        assert main(["call", "run_status", "--arg", "run_id=does-not-exist"]) == 1
        assert json.loads(capsys.readouterr().out)["error"] == "invalid_input"
        assert main(["call", "injection_info", "--arg", "injection_class=ssti"]) == 0
        assert json.loads(capsys.readouterr().out)["id"] == "ssti"
    finally:
        for store in vars(context).values():
            close = getattr(store, "close", None)
            if callable(close):
                close()


async def test_real_stdio_execution_errors_and_structured_content(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MOONMCP_")}
    env["MOONMCP_STATE_DIR"] = str(tmp_path)
    params = StdioServerParameters(command=sys.executable, args=["-m", "moonmcp"], env=env)

    async def check():
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                result = await session.call_tool("run_status", {"run_id": "does-not-exist"})
                assert result.isError is True
                assert result.structuredContent["error"] == "invalid_input"
                assert json.loads(result.content[0].text) == result.structuredContent
                blocked = await session.call_tool("http_probe", {"target": "https://not-authorised.test"})
                assert blocked.isError is True
                assert blocked.structuredContent["error"] == "out_of_scope"
                success = await session.call_tool("injection_info", {"injection_class": "ssti"})
                assert success.isError is False
                assert success.structuredContent["id"] == "ssti"

    await asyncio.wait_for(check(), timeout=30)
