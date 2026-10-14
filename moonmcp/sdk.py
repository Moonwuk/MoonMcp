"""The single compatibility boundary for the supported MCP 1.x SDK.

Application modules use these functions rather than SDK private managers or
function metadata. Filtering uses the SDK's public remove_tool API. Native
validation/conversion are retained; no schemas or gate wrappers are recreated.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import CallToolResult, TextContent, Tool


def _manager(server: Any) -> Any:
    manager = getattr(server, "_tool_manager", None)
    if manager is None:
        raise RuntimeError("Unsupported MCP SDK: missing tool manager; MoonMCP requires mcp>=1.30,<2")
    return manager


def _metadata(tool: Any) -> Any:
    metadata = getattr(tool, "fn_metadata", None)
    if metadata is None:
        raise RuntimeError("Unsupported MCP SDK: missing tool function metadata")
    return metadata


def list_registered(server: Any) -> list[Any]:
    """Logical profile-filtered tools; includes compact tools with hidden schemas."""
    return list(_manager(server).list_tools())


def registered_tools(server: Any) -> dict[str, Any]:
    return {tool.name: tool for tool in list_registered(server)}


def get_registered(server: Any, name: str) -> Any:
    return _manager(server).get_tool(name)


def retain_tools(server: Any, allowed: set[str]) -> None:
    for name in set(registered_tools(server)) - allowed:
        server.remove_tool(name)


async def call_registered(server: Any, name: str, arguments: dict[str, Any], *,
                          context: Any = None) -> Any:
    """Validate and invoke an already-gated callable, preserving Python results."""
    return await _manager(server).call_tool(name, arguments, context=context, convert_result=False)


def validate_arguments(tool: Any, arguments: dict[str, Any]) -> tuple[dict, dict]:
    parsed = _metadata(tool).arg_model.model_validate(arguments, strict=True)
    return parsed.model_dump_one_level(), parsed.model_dump(mode="json")


def output_schema(tool: Any) -> dict[str, Any] | None:
    return _metadata(tool).output_schema


def convert_result(tool: Any, result: Any) -> Any:
    return _metadata(tool).convert_result(result)


def requires_context(tool: Any) -> bool:
    return getattr(tool, "context_kwarg", None) is not None


def set_server_version(server: Any, version: str) -> None:
    server._mcp_server.version = version


class MoonMCPFastMCP(FastMCP):
    """Adapt at the protocol boundary so nested Python calls remain compatible."""

    advertised_tools: set[str] | None = None

    async def list_tools(self) -> list[Tool]:
        tools = await super().list_tools()
        if self.advertised_tools is None:
            return tools
        return [tool for tool in tools if tool.name in self.advertised_tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if self.advertised_tools is not None and name not in self.advertised_tools:
            raise ToolError(f"Tool {name!r} is not advertised; use the execution facade.")
        tool = get_registered(self, name)
        # The manager keeps SDK validation and profile-filtered lookup intact.
        result = await call_registered(self, name, arguments, context=self.get_context())
        if isinstance(result, CallToolResult):
            return result
        if isinstance(result, dict):
            from .outcomes import failure

            error = failure(result)
            # Validate typed output when a new tool declares it. Legacy dict
            # tools have no output schema and keep their existing shape.
            if error is None and tool is not None and output_schema(tool) is not None:
                convert_result(tool, result)
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
                structuredContent=result,
                isError=error is not None,
                _meta={"moonmcp.outcome": asdict(error)} if error else None,
            )
        # Preserve SDK handling of images, resource links and non-object results.
        assert tool is not None
        return convert_result(tool, result)
