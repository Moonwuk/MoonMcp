"""Transport adapters for legacy tool outcomes.

Python callers retain the original result. MCP clients receive the same JSON
object as structured content and an execution error flag; a negative research
verdict (for example ``unconfirmed``) is a successful tool execution.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.types import CallToolResult


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


# Compatibility import for existing Python clients. SDK internals live in sdk.py.
from .sdk import MoonMCPFastMCP as MoonMCPFastMCP  # noqa: E402
