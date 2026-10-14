"""Transport adapters for legacy tool outcomes.

Python callers retain the original result. MCP clients receive the same JSON
object as structured content and an execution error flag; a negative research
verdict (for example ``unconfirmed``) is a successful tool execution.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import CallToolResult, TextContent, Tool


@dataclass(frozen=True)
class Failure:
    code: str
    retryable: bool
    recovery: str


_RECOVERY = {
    "out_of_scope": "Check the authorised scope before choosing another action.",
    "disabled": "Check the engagement policy and configured capabilities.",
    "missing_dependency": "Install or configure the dependency, or choose an available tool.",
    "invalid_input": "Correct the arguments before retrying.",
    "budget_exhausted": "Stop this action and review the run budget.",
    "rate_limited": "Respect the reported retry delay before another attempt.",
    "timeout": "Review the timeout and remaining request budget before retrying.",
    "internal_error": "Inspect the server diagnostics before retrying.",
}


def failure(result: object) -> Failure | None:
    """Classify a top-level execution error, never nested detector observations."""
    if isinstance(result, CallToolResult):
        return Failure("tool_error", False, "Inspect the tool result.") if result.isError else None
    if not isinstance(result, dict) or not result.get("error"):
        return None
    code = str(result["error"])
    detail = str(result.get("detail", "")).lower()
    if code == "invalid_input" and detail.startswith("budget exceeded:"):
        code = "budget_exhausted"
    elif result.get("available") is False and result.get("install_hint"):
        code = "missing_dependency"
    recovery = str(result.get("hint") or result.get("install_hint") or
                   _RECOVERY.get(code, "Inspect the error and correct its cause before retrying."))
    return Failure(code, code in {"rate_limited", "timeout"}, recovery)


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
        tool = self._tool_manager.get_tool(name)
        # The manager keeps SDK validation and profile-filtered lookup intact.
        result = await self._tool_manager.call_tool(
            name, arguments, context=self.get_context(), convert_result=False,
        )
        if isinstance(result, CallToolResult):
            return result
        if isinstance(result, dict):
            error = failure(result)
            # Validate typed output when a new tool declares it. Legacy dict
            # tools have no output schema and keep their existing shape.
            if error is None and tool is not None and tool.fn_metadata.output_schema is not None:
                tool.fn_metadata.convert_result(result)
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
                structuredContent=result,
                isError=error is not None,
                _meta={"moonmcp.outcome": asdict(error)} if error else None,
            )
        # Preserve SDK handling of images, resource links and non-object results.
        assert tool is not None
        return tool.fn_metadata.convert_result(result)
