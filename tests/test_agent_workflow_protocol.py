"""Exercise discovery, flags and profile boundaries through a real stdio client."""

import asyncio
import hashlib
import json
import os
import sys
from contextlib import asynccontextmanager

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TARGET = "workflow.test"
PROJECT = "protocol-fixture"


@asynccontextmanager
async def _session(state_dir, **configuration):
    env = {key: value for key, value in os.environ.items() if not key.startswith("MOONMCP_")}
    env.update(MOONMCP_STATE_DIR=str(state_dir), MOONMCP_SCOPE=TARGET, **configuration)
    params = StdioServerParameters(command=sys.executable, args=["-m", "moonmcp"], env=env)
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as client:
            initialized = await client.initialize()
            assert initialized.serverInfo.name == "moonmcp"
            yield client


async def _ok(client, _tool, **arguments):
    result = await client.call_tool(_tool, arguments)
    assert result.isError is False, (_tool, result)
    assert isinstance(result.structuredContent, dict), (_tool, result)
    assert json.loads(result.content[0].text) == result.structuredContent
    return result.structuredContent


async def _error(client, _tool, code=None, **arguments):
    result = await client.call_tool(_tool, arguments)
    assert result.isError is True, (_tool, result)
    if code:
        assert result.structuredContent["error"] == code, (_tool, result)
    return result


def _observation(**extra):
    return {
        "project": PROJECT, "target": TARGET,
        "observation": "The captured application bundle refers to a legacy API route.",
        "evidence": [{"ref": "fixture://bundle/app.js", "source_group": "bundle-response-1"}],
        "entities": ["/api/v1/profile"], "auth_context": "anonymous", **extra,
    }


async def _inventory(client):
    listed = await client.list_tools()
    assert listed.nextCursor is None
    names = {tool.name for tool in listed.tools}
    assert len(names) == len(listed.tools)
    schemas = [tool.model_dump(mode="json", by_alias=True, exclude_none=True) for tool in listed.tools]
    size = len(json.dumps(schemas, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return names, size


async def test_full_and_compact_discovery_flags_and_schema_cost(tmp_path, record_property):
    async def check():
        async with _session(tmp_path / "full") as full:
            full_names, full_bytes = await _inventory(full)
            assert {"flag_record", "run_execute", "injection_info"} <= full_names
            direct = await _ok(full, "flag_record", **_observation())
            assert direct["flag"]["project"] == PROJECT
            assert direct["flag"]["status"] == "new"
            assert direct["flag"]["trust"] == "untrusted"

        async with _session(tmp_path / "compact", MOONMCP_COMPACT="1") as compact:
            compact_names, compact_bytes = await _inventory(compact)
            assert {"tool_search", "tool_describe", "run_start", "run_execute"} <= compact_names
            assert {"flag_record", "injection_info"}.isdisjoint(compact_names)
            assert compact_names < full_names
            assert compact_bytes < full_bytes / 3
            status = await _ok(compact, "server_status")
            assert status["compact_mode"] is True
            assert status["tools_advertised"] == len(compact_names)
            assert status["tools_exposed"] == len(full_names)
            measurements = {"full_tools": len(full_names), "compact_tools": len(compact_names),
                            "full_schema_bytes": full_bytes, "compact_schema_bytes": compact_bytes,
                            "schema_bytes_reduction_percent": round(100 * (1 - compact_bytes / full_bytes), 2)}
            for key, value in measurements.items():
                record_property(key, value)
            print("\nstdio_schema_measurements=" + json.dumps(measurements, sort_keys=True))

            candidates = await _ok(compact, "tool_search", query="flag_record")
            assert candidates["candidates"][0]["name"] == "flag_record"
            description = await _ok(compact, "tool_describe", name="flag_record")
            assert description["name"] == "flag_record"
            assert {"project", "target", "observation", "evidence"} <= set(description["input_schema"]["required"])
            assert description["request_accounting"] == "local"
            await _error(compact, "flag_record", **_observation())

            run = await _ok(compact, "run_start", target=TARGET, focus="offline flag workflow")
            run_id = run["run"]["id"]
            # A flag invoked through the dispatcher inherits its executing run.
            arguments = _observation()
            recorded = await _ok(compact, "run_execute", run_id=run_id, tool_name="flag_record",
                                 arguments=arguments, idempotency_key="observation-1")
            flag = recorded["data"]["flag"]
            assert recorded["ok"] is True and recorded["state"] == "completed"
            assert recorded["requests"] == 0
            assert flag["project"] == PROJECT and flag["target"] == TARGET
            assert flag["run_id"] == run_id and flag["trust"] == "untrusted"
            replay = await _ok(compact, "run_execute", run_id=run_id, tool_name="flag_record",
                               arguments=arguments, idempotency_key="observation-1")
            assert replay["replayed"] is True
            assert replay["data"]["flag"]["id"] == flag["id"]

            brief = await _ok(compact, "run_brief", run_id=run_id, project=PROJECT)
            assert brief["run"]["budget"]["tool_calls"]["used"] == 1
            assert brief["run"]["budget"]["requests"]["used"] == 0
            assert flag["id"] in json.dumps(brief["analysis"])
            await _error(compact, "run_execute", "invalid_input", run_id=run_id,
                         tool_name="flag_record", arguments=_observation(target="other.test"))
            await _error(compact, "run_execute", "invalid_input", run_id=run_id,
                         tool_name="flag_record", arguments={"target": TARGET})
            other_run = (await _ok(compact, "run_start", target=TARGET))["run"]["id"]
            await _error(compact, "run_execute", "invalid_input", run_id=run_id,
                         tool_name="flag_record", arguments=_observation(run_id=other_run))
            await _error(compact, "run_execute", "invalid_input", run_id=run_id,
                         tool_name="flag_get", arguments={"project": "other-project", "flag_id": flag["id"]})

    await asyncio.wait_for(check(), timeout=45)


async def test_knowledge_profile_compact_falls_back_to_usable_direct_tools(tmp_path):
    async def check():
        async with _session(tmp_path, MOONMCP_PROFILE="knowledge", MOONMCP_COMPACT="1") as client:
            names, _ = await _inventory(client)
            assert {"injection_info", "flag_record", "tool_describe"} <= names
            assert {"run_start", "run_execute", "http_probe"}.isdisjoint(names)
            status = await _ok(client, "server_status")
            assert status["compact_mode"] is False
            assert (await _ok(client, "injection_info", injection_class="ssti"))["id"] == "ssti"
            assert (await _ok(client, "flag_record", **_observation()))["created"] is True
            await _error(client, "tool_describe", "tool_unavailable", name="http_probe")
            await _error(client, "http_probe", target=f"https://{TARGET}")
            await _error(client, "run_execute", run_id="missing", tool_name="http_probe", arguments={})

    await asyncio.wait_for(check(), timeout=30)


@pytest.mark.parametrize("configuration,hidden", [
    ({"MOONMCP_PROFILE": "knowledge", "MOONMCP_EXPOSE_TOOLS": "run_start,run_execute"}, "http_probe"),
    ({"MOONMCP_HIDE_TOOLS": "flag_record"}, "flag_record"),
])
async def test_compact_dispatch_cannot_bypass_logical_profile(tmp_path, configuration, hidden):
    async def check():
        async with _session(tmp_path, MOONMCP_COMPACT="1", **configuration) as client:
            names, _ = await _inventory(client)
            assert "run_execute" in names and hidden not in names
            assert (await _ok(client, "server_status"))["compact_mode"] is True
            candidates = await _ok(client, "tool_search", query=hidden, available_only=False)
            assert hidden not in {item["name"] for item in candidates["candidates"]}
            await _error(client, "tool_describe", "tool_unavailable", name=hidden)
            run = await _ok(client, "run_start", target=TARGET)
            await _error(client, "run_execute", "tool_unavailable", run_id=run["run"]["id"],
                         tool_name=hidden, arguments={})

    await asyncio.wait_for(check(), timeout=30)


async def test_compact_artifact_resource_and_chunk_read_preserve_evidence(tmp_path):
    async def check():
        async with _session(tmp_path, MOONMCP_COMPACT="1") as client:
            run_id = (await _ok(client, "run_start", target=TARGET))["run"]["id"]
            content = "Наблюдение: маршрут /api/v1/profile\n" * 400
            artifact = (await _ok(client, "run_artifact_add", run_id=run_id, kind="evidence",
                                  name="captured-response.txt", content=content))["artifact"]
            resources = await client.list_resource_templates()
            assert any(str(item.uriTemplate) == "moonmcp://runs/{run_id}/artifacts/{artifact_id}"
                       for item in resources.resourceTemplates)
            resource = await client.read_resource(artifact["uri"])
            chunk = json.loads(resource.contents[0].text)
            parts = [chunk["content"]]
            assert chunk["next_offset"] is not None
            while chunk["next_offset"] is not None:
                chunk = await _ok(client, "run_artifact_read", run_id=run_id,
                                  artifact_id=artifact["id"], offset=chunk["next_offset"], limit=1024)
                parts.append(chunk["content"])
            recovered = "".join(parts)
            assert recovered == content
            assert hashlib.sha256(recovered.encode()).hexdigest() == artifact["sha256"]
            other_run = (await _ok(client, "run_start", target=TARGET))["run"]["id"]
            await _error(client, "run_artifact_read", "invalid_input", run_id=other_run,
                         artifact_id=artifact["id"])

    await asyncio.wait_for(check(), timeout=30)
