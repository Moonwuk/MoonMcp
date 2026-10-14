"""Execution status must agree across transports without reading detector prose."""

import asyncio
import json

import pytest
from mcp.types import CallToolResult, ImageContent, TextContent

from moonmcp import pipeline, sdk, server
from moonmcp.__main__ import main
from moonmcp.outcomes import RESULT_META, TextFailure, envelope, failure, outcome, safe_tool


@pytest.mark.parametrize("payload", [
    {"verdict": "unconfirmed", "confirmed": False},
    {"success": False, "observations": [{"error": "endpoint unavailable"}]},
    {"state": "failed", "id": "queried-run"},
    {"state": "unknown", "observation": "hypothesis status"},
    {"available": False},
    "Ошибка чтения: this is quoted research, not execution status",
    {"data": {"error": "timeout"}},
])
def test_observations_are_not_execution_errors(payload):
    assert outcome(payload).ok
    assert envelope(payload)["data"] == payload


@pytest.mark.parametrize("payload,state,code", [
    ({"ok": False, "state": "partial"}, "partial", "partial_result"),
    ({"ok": False, "state": "unknown"}, "unknown", "outcome_unknown"),
    ({"ok": False, "state": "cancelled"}, "cancelled", "cancelled"),
    ({"ok": False, "state": "blocked"}, "blocked", "blocked"),
    ({"ok": True, "state": "partial"}, "partial", "partial_result"),
    ({"ok": True, "error": "internal_error"}, "failed", "internal_error"),
    ({"error": "out_of_scope"}, "blocked", "out_of_scope"),
    ({"error": "Connection refused: 127.0.0.1"}, "failed", "tool_error"),
    (TextFailure("Missing index", "missing_dependency"), "blocked", "missing_dependency"),
])
def test_failure_contract(payload, state, code):
    result = envelope(payload)
    assert result["version"] == 1
    assert result["state"] == state
    assert result["ok"] is False
    assert result["error"]["code"] == code
    assert result["error"]["recovery"]
    assert result["data"] == payload


def test_retry_denial_and_recovery_from_receipts_are_preserved():
    error = failure({"error": "rate_limited", "retryable": False, "recovery": "Wait for review."})
    assert error.retryable is False
    assert error.recovery == "Wait for review."
    assert failure({"error": "timeout"}).retryable is False
    assert failure({"error": "connection refused"}).message == "connection refused"


async def test_protocol_preserves_native_content_and_metadata():
    application = sdk.MoonMCPFastMCP("content")
    original = CallToolResult(content=[ImageContent(type="image", data="aGVsbG8=", mimeType="image/png")],
                              _meta={"producer": "fixture"})

    @application.tool()
    async def native() -> CallToolResult:
        return original

    result = await application.call_tool("native", {})
    assert result.content == original.content
    assert result.meta["producer"] == "fixture"
    assert result.meta[RESULT_META] == outcome(original).metadata()
    assert original.meta == {"producer": "fixture"}


async def test_protocol_validation_and_unknown_tools_share_contract():
    application = sdk.MoonMCPFastMCP("validation")
    calls = []

    @application.tool()
    async def integer(value: int) -> dict:
        calls.append(value)
        return {"value": value}

    for name, args, code in [("missing", {}, "unknown_tool"),
                             ("integer", {"value": "wrong"}, "invalid_input")]:
        result = await application.call_tool(name, args)
        assert result.isError
        assert result.meta[RESULT_META]["error"]["code"] == code
        assert json.loads(result.content[0].text) == result.structuredContent
    assert calls == []


async def test_text_error_and_success_have_identical_status_contract(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_PIPELINE_DIRS", [tmp_path])
    missing = await server.get_nuclei_template("missing")
    assert isinstance(missing, str)
    assert failure(missing).code == "missing_dependency"
    protocol = await server.mcp.call_tool("get_nuclei_template", {"template_id": "missing"})
    assert protocol.isError
    assert protocol.content[0].text == missing
    assert protocol.structuredContent is None
    assert protocol.meta[RESULT_META] == outcome(missing).metadata()
    empty = await server.mcp.call_tool("list_queue", {})
    assert not empty.isError
    assert empty.meta[RESULT_META]["state"] == "completed"


def test_cli_envelope_keeps_data_and_reports_text_errors(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(pipeline, "_PIPELINE_DIRS", [tmp_path])
    assert main(["call", "get_nuclei_template", "--arg", "template_id=missing", "--envelope"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["error"]["code"] == "missing_dependency"
    assert isinstance(result["data"], str)
    assert main(["call", "list_queue", "--envelope"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "completed"
    assert main(["call", "http_probe", "--envelope"]) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "invalid_input"


def test_protocol_flag_overrides_untrusted_or_future_metadata():
    for meta in [{"version": 2, "state": "completed", "ok": True, "error": None},
                 outcome({}).metadata(), {"version": 1, "state": [], "ok": False}]:
        result = CallToolResult(content=[TextContent(type="text", text="bad")], isError=True,
                                _meta={RESULT_META: meta})
        assert failure(result).code == "tool_error"


async def test_guard_preserves_cancellation_and_marks_timeout():
    @safe_tool
    async def interrupted():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await interrupted()

    @safe_tool
    async def timed_out():
        raise TimeoutError("worker may have completed")

    error = failure(await timed_out())
    assert error.code == "timeout"
    assert error.retryable is False


async def test_unknown_argument_is_rejected_before_side_effect_in_mcp_and_cli(monkeypatch, capsys):
    application = sdk.MoonMCPFastMCP("no-ignored-arguments")
    calls = []

    @application.tool()
    async def action(count: int = 1) -> dict:
        calls.append(count)
        return {"count": count}

    result = await application.call_tool("action", {"coutn": 2})
    assert result.isError
    assert result.meta[RESULT_META]["error"]["code"] == "invalid_input"
    assert "coutn" in result.structuredContent["detail"]
    assert calls == []

    monkeypatch.setattr(server, "mcp", application)
    # Run the synchronous CLI in a thread; it owns its own asyncio.run loop.
    code = await asyncio.to_thread(main, ["call", "action", "--arg", "coutn=2", "--envelope"])
    assert code == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "invalid_input"
    assert calls == []


def test_missing_reference_index_differs_from_successful_empty_lookup(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_PIPELINE_DIRS", [tmp_path])
    assert failure(pipeline.check_subdomain_takeover("missing")).code == "missing_dependency"
    folder = tmp_path / "knowledge_base" / "subdomain_takeover"
    folder.mkdir(parents=True)
    (folder / "fingerprints.json").write_text("[]")
    assert failure(pipeline.check_subdomain_takeover("missing")) is None
