"""Protect the single MCP SDK boundary, especially validation and filtering."""

from types import SimpleNamespace

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel, ValidationError

from moonmcp import sdk
from moonmcp.outcomes import MoonMCPFastMCP


def test_legacy_class_import_points_to_the_sdk_adapter():
    assert MoonMCPFastMCP is sdk.MoonMCPFastMCP


def test_unsupported_sdk_layout_reports_a_clear_error():
    with pytest.raises(RuntimeError, match="Unsupported MCP SDK"):
        sdk.list_registered(SimpleNamespace())
    with pytest.raises(RuntimeError, match="function metadata"):
        sdk.validate_arguments(SimpleNamespace(), {})


async def test_filtering_removes_tools_from_validation_and_invocation():
    application = MoonMCPFastMCP("filtered")
    called = []

    @application.tool()
    async def allowed(value: int) -> dict:
        called.append(value)
        return {"value": value}

    @application.tool()
    async def hidden() -> dict:
        raise AssertionError("filtered tool must not execute")

    sdk.retain_tools(application, {"allowed"})
    assert set(sdk.registered_tools(application)) == {"allowed"}
    with pytest.raises(ToolError):
        await sdk.call_registered(application, "hidden", {})
    tool = sdk.get_registered(application, "allowed")
    with pytest.raises(ValidationError):
        sdk.validate_arguments(tool, {"value": "not-an-integer"})
    assert called == []
    assert await sdk.call_registered(application, "allowed", {"value": 3}) == {"value": 3}
    assert called == [3]


async def test_structured_output_validation_survives_protocol_adapter():
    class Answer(BaseModel):
        count: int

    application = MoonMCPFastMCP("typed-output")

    # A local model with future annotations needs a resolved annotation for SDK hints.
    async def typed():
        return {"count": "wrong"}
    typed.__annotations__["return"] = Answer
    application.add_tool(typed)
    result = await application.call_tool("typed", {})
    assert result.isError
    assert result.structuredContent["error"] == "output_validation_error"
