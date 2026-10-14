"""Extracted families bind context per server and preserve legacy protocol data."""

import json
from types import SimpleNamespace

from moonmcp import pipeline, sdk, server
from moonmcp.families import memory
from moonmcp.families import pipeline as pipeline_tools
from moonmcp.memory import MemoryStore


async def test_memory_family_registrations_do_not_share_context():
    stores = [MemoryStore(), MemoryStore()]
    try:
        applications = [sdk.MoonMCPFastMCP("first"), sdk.MoonMCPFastMCP("second")]
        exports = []
        for application, store in zip(applications, stores, strict=True):
            ctx = SimpleNamespace(memory=store)
            exports.append(memory.register(application, server.safe_tool,
                                           lambda ctx=ctx: ctx, server._host_key))
        created = await exports[0]["memory_add"]("note", "First context only", target="example.test")
        assert (await exports[0]["memory_get"](created["id"]))["title"] == "First context only"
        assert (await exports[1]["memory_get"](created["id"]))["error"] == "not_found"
        protocol = await applications[0].call_tool("memory_get", {"item_id": created["id"]})
        assert not protocol.isError
        assert protocol.structuredContent["title"] == "First context only"
        assert exports[0]["memory_get"] is not exports[1]["memory_get"]
    finally:
        for store in stores:
            store.close()


async def test_pipeline_text_keeps_legacy_schema_and_wire_shape(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_PIPELINE_DIRS", [tmp_path])
    application = sdk.MoonMCPFastMCP("pipeline")
    exports = pipeline_tools.register(application, server.safe_tool)
    assert isinstance(await exports["list_queue"](), str)
    before = await exports["list_queue"]()
    protocol = await application.call_tool("list_queue", {})
    assert protocol[0].text == before
    described = next(t for t in await application.list_tools() if t.name == "list_queue")
    assert described.outputSchema is None
    assert sdk.output_schema(sdk.get_registered(application, "list_queue")) is None


def test_family_imports_are_safe_without_loading_server(tmp_path):
    import os
    import subprocess
    import sys

    environment = dict(os.environ, MOONMCP_STATE_DIR=str(tmp_path / "unused-state"))
    code = """
import json, sys
from moonmcp.families import knowledge, memory, pipeline, reporting, runs
print(json.dumps({'server_loaded': 'moonmcp.server' in sys.modules}))
"""
    completed = subprocess.run([sys.executable, "-c", code], env=environment, check=True,
                               capture_output=True, text=True, timeout=15)
    assert json.loads(completed.stdout) == {"server_loaded": False}
    assert not (tmp_path / "unused-state").exists()


def test_extracted_tools_remain_available_as_python_server_exports():
    for name in ("injection_info", "memory_brief", "run_start", "add_finding", "list_queue"):
        registered = sdk.get_registered(server.mcp, name)
        assert registered.fn is getattr(server, name)
        assert registered.fn.__module__.startswith("moonmcp.families.")
