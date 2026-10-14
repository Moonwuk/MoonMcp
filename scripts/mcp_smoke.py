"""Exercise the installed wheel through MCP stdio, without importing source.

Run with the wheel environment's Python: ``python -I scripts/mcp_smoke.py``.
The server runs from a temporary cwd with isolated state and Python import paths.
Only local reference lookup and a deliberately invalid run lookup are invoked.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def smoke(workdir: Path) -> dict:
    repository = Path(__file__).resolve().parent.parent
    spec = importlib.util.find_spec("moonmcp")
    if spec is None or not spec.origin:
        raise AssertionError("MoonMCP must be installed before running the wheel smoke test")
    installed_path = Path(spec.origin).resolve()
    if installed_path.is_relative_to(repository):
        raise AssertionError(f"Wheel smoke resolved a source checkout: {installed_path}")

    env = {key: value for key, value in os.environ.items()
           if not key.startswith("MOONMCP_") and key != "PYTHONPATH"}
    env["MOONMCP_STATE_DIR"] = str(workdir / "state")
    params = StdioServerParameters(command=sys.executable, args=["-I", "-m", "moonmcp"],
                                   cwd=str(workdir), env=env)
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            listed = await session.list_tools()
            names = {tool.name for tool in listed.tools}
            assert {"injection_info", "run_status"} <= names, "required tools missing"
            assert len(names) == len(listed.tools), "duplicate tool names"
            assert listed.nextCursor is None, "smoke must cover all advertised tools"

            reference = await session.call_tool("injection_info", {"injection_class": "ssti"})
            assert reference.isError is False, reference
            assert reference.structuredContent is not None
            assert reference.structuredContent["id"] == "ssti"

            invalid = await session.call_tool("run_status", {"run_id": "missing-smoke-run"})
            assert invalid.isError is True, "application error was reported as protocol success"
            assert invalid.structuredContent is not None
            assert invalid.structuredContent["error"] == "invalid_input"
            assert json.loads(invalid.content[0].text) == invalid.structuredContent

    return {"server": initialized.serverInfo.name, "tools": len(names),
            "installed_package": str(installed_path), "structured_success": True,
            "structured_error": True, "checks": ["local_reference", "missing_run"]}


def main() -> None:
    with TemporaryDirectory(prefix="moonmcp-wheel-smoke-") as directory:
        result = asyncio.run(asyncio.wait_for(smoke(Path(directory)), timeout=30))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
