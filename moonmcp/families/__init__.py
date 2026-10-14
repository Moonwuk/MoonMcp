"""Tool families with explicit registration and injected application context."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def local_registration(mcp: Any, safe_tool: Callable, exported: dict, *,
                       structured_output: bool | None = None) -> Callable:
    """Register one local wrapper and retain the callable for Python compatibility."""
    def local(fn: Callable) -> Callable:
        # Nesting these definitions adds one indentation level to raw docstrings.
        # Preserve the exact descriptions already published by the MCP server.
        if fn.__doc__:
            fn.__doc__ = "\n".join(line[4:] if line.startswith("    ") else line
                                   for line in fn.__doc__.split("\n"))
        wrapped = safe_tool(fn)
        mcp.tool(structured_output=structured_output)(wrapped)
        exported[fn.__name__] = wrapped
        return wrapped
    return local
