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


class ArgumentError(ValueError):
    """Arguments not accepted by the registered tool's public schema."""


def validate_argument_names(tool: Any, arguments: dict[str, Any]) -> None:
    unknown = set(arguments) - set(tool.parameters.get("properties", {}))
    if unknown:
        raise ArgumentError("unknown tool arguments: " + ", ".join(sorted(unknown)))


async def call_registered(server: Any, name: str, arguments: dict[str, Any], *,
                          context: Any = None) -> Any:
    """Validate and invoke an already-gated callable, preserving Python results."""
    tool = get_registered(server, name)
    if tool is not None:
        try:
            validate_argument_names(tool, arguments)
        except ArgumentError as exc:
            raise ToolError(str(exc)) from exc
    result = await _manager(server).call_tool(name, arguments, context=context, convert_result=False)
    return checked_result(tool, result)


def validate_arguments(tool: Any, arguments: dict[str, Any]) -> tuple[dict, dict]:
    metadata = _metadata(tool)
    validate_argument_names(tool, arguments)
    parsed = metadata.arg_model.model_validate(arguments, strict=True)
    return parsed.model_dump_one_level(), parsed.model_dump(mode="json")


def output_schema(tool: Any) -> dict[str, Any] | None:
    return _metadata(tool).output_schema


def convert_result(tool: Any, result: Any) -> Any:
    return _metadata(tool).convert_result(result)


def checked_result(tool: Any, result: Any) -> Any:
    """Validate declared output once at each invocation boundary, before caching."""
    from .outcomes import outcome

    if (tool is None or isinstance(result, CallToolResult) or not outcome(result).ok
            or output_schema(tool) is None):
        return result
    try:
        convert_result(tool, result)
    except ValueError as exc:
        return {"error": "output_validation_error", "detail": str(exc)}
    return result


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
        from pydantic import ValidationError

        from .outcomes import RESULT_META, outcome

        tool = get_registered(self, name)
        if self.advertised_tools is not None and name not in self.advertised_tools:
            result = {"error": "tool_not_advertised",
                      "detail": f"Tool {name!r} is not advertised; use the execution facade."}
        elif tool is None:
            result = {"error": "unknown_tool", "detail": f"Unknown tool: {name}"}
        else:
            try:
                result = await call_registered(self, name, arguments, context=self.get_context())
            except ToolError as exc:
                result = {"error": "invalid_input" if isinstance(exc.__cause__, (ValidationError, ArgumentError))
                          else "internal_error", "detail": str(exc)}

        status = outcome(result)
        if isinstance(result, CallToolResult):
            protocol = result.model_copy(deep=True)
        elif isinstance(result, dict):
            protocol = CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
                structuredContent=result,
            )
        else:
            assert tool is not None
            try:
                converted = convert_result(tool, result)
                if isinstance(converted, CallToolResult):
                    protocol = converted.model_copy(deep=True)
                elif isinstance(converted, tuple):
                    protocol = CallToolResult(content=converted[0], structuredContent=converted[1])
                else:
                    protocol = CallToolResult(content=converted)
            except (ValidationError, ValueError) as exc:
                payload = {"error": "output_validation_error", "detail": str(exc)}
                status = outcome(payload)
                protocol = CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(payload))],
                    structuredContent=payload,
                )
        metadata = dict(protocol.meta or {})
        metadata[RESULT_META] = status.metadata()
        # Retain the original error-only key for clients already consuming it.
        if status.error:
            metadata["moonmcp.outcome"] = asdict(status.error)
        protocol.meta = metadata
        protocol.isError = not status.ok
        return protocol
