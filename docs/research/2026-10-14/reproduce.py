"""Offline audit probes; run with MoonMCP checkout on PYTHONPATH.

Temporary stores only. No target HTTP requests, credentials, or real findings.
"""
import asyncio
import json
import os
import sys
import tempfile
from datetime import timedelta
from importlib.metadata import version
from pathlib import Path
from unittest.mock import patch

from moonmcp.memory import MemoryStore


def memory_probes():
    store = MemoryStore()
    store.add(kind="finding", title="unrelated host", target="https://notexample.com/a")
    host_collision = store.brief("example.com")["findings"]
    store.clear()
    store.add(kind="finding", title="older relevant finding", target="https://example.com/a")
    for n in range(205):
        store.add(kind="observation", title=f"unrelated {n}", target="other.test")
    omitted = store.brief("example.com")
    store.clear()
    item = store.add(kind="lesson", title="same key", target="example.com",
                     body="reviewed content", trust="curated")
    store.add(kind="lesson", title="same key", target="example.com",
              body="unreviewed replacement", trust="untrusted")
    overwritten = store.get(item)
    store.close()
    return {"host_collision": host_collision, "older_target_brief": omitted,
            "trust_after_untrusted_overwrite": overwritten}


def baseline_probes(state):
    from moonmcp import bench, server
    from moonmcp.config import Settings
    from moonmcp.context import build_context
    previous = server._CTX
    with patch.dict(os.environ, {"MOONMCP_STATE_DIR": str(state)}):
        server._CTX = build_context(Settings(scope=["baseline.test"], state_dir=str(state)))
        try:
            first = asyncio.run(server.run_start("baseline.test"))
            first_task = first["next"]["id"]
            before = server._CTX.runs.task(first_task)
            with patch.object(Path, "home", return_value=state):
                bench.scenario_run_continuation()
            after = server._CTX.runs.task(first_task)
            budget = bench.scenario_budget_exhausted()
            budget_run = asyncio.run(server.run_start("baseline.test", max_requests=1))
            refused = asyncio.run(server.run_usage(budget_run["run"]["id"], requests=5))
            return {"earlier_run_task": {"id": first_task, "before": before["state"],
                                         "after": after["state"]},
                    "budget_scenario_notes": budget.notes, "actual_budget_refusal": refused}
        finally:
            server._CTX.runs.close()
            server._CTX.memory.close()
            server._CTX = previous


async def protocol_probe(state):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    params = StdioServerParameters(command=sys.executable, args=["-m", "moonmcp"],
        env={**os.environ, "MOONMCP_STATE_DIR": str(state), "MOONMCP_PROFILE": "full",
             "MOONMCP_EXPOSE_TOOLS": "", "MOONMCP_HIDE_TOOLS": ""})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10)) as client:
            await client.initialize()
            tools = await client.list_tools()
            result = await client.call_tool("run_status", {"run_id": "audit-missing-run"})
            return {"tools_count_first_page": len(tools.tools), "next_cursor": tools.nextCursor,
                    "output_schema_count": sum(t.outputSchema is not None for t in tools.tools),
                    "error_result": result.model_dump(mode="json", exclude_none=True)}


with tempfile.TemporaryDirectory(prefix="moonmcp-audit-") as scratch:
    state = Path(scratch)
    result = {"sdk_version": version("mcp"), "memory": memory_probes(),
              "baseline": baseline_probes(state / "baseline"),
              "protocol": asyncio.run(protocol_probe(state / "protocol"))}
    print(json.dumps(result, ensure_ascii=False, indent=2))
