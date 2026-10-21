"""External CLI bounds using local Python children; no scanners or remote targets."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from moonmcp import server as srv
from moonmcp.external import cli
from moonmcp.outcomes import outcome

_TARGET = "https://127.0.0.1"


@pytest.fixture()
def python_tool(monkeypatch):
    # Invoke Python through a known network-tool entry. The real tool registry
    # and direct-Python scope gate remain active; no security CLI is installed.
    monkeypatch.setattr(cli, "tool_path", lambda _tool: sys.executable)

    async def run(source, **kwargs):
        return await cli.run_tool(
            "httpx", ["-u", "-c", source],
            scope_check=lambda target: target == _TARGET, targets=[_TARGET], **kwargs,
        )

    return run


async def _reap(proc):
    if proc.returncode is None:
        proc.kill()
    await proc.wait()


@pytest.mark.asyncio
async def test_stdin_streams_and_nonzero_exit_are_preserved(python_tool):
    result = await python_tool(
        "import sys; print(sys.stdin.read().upper()); "
        "print('diagnostic', file=sys.stderr); sys.exit(7)",
        stdin="hello", timeout=3,
    )
    assert result.stdout == "HELLO\n"
    assert result.stderr == "diagnostic\n"
    assert result.exit_code == 7 and result.error == "command_failed"
    assert result.cleanup_confirmed and not result.truncated
    assert result.duration_ms > 0 and result.available


@pytest.mark.asyncio
async def test_stdin_backpressure_does_not_block_stdout_stderr_draining(python_tool):
    result = await python_tool(
        "import os,sys; os.write(1,b'O'*131072); "
        "data=sys.stdin.buffer.read(); print(len(data)); os.write(2,b'E'*100)",
        stdin="x" * 524288, max_output_bytes=200000, timeout=3,
    )
    assert result.stdout == "O" * 131072 + "524288\n"
    assert result.stderr == "E" * 100
    assert result.error is None and result.cleanup_confirmed


@pytest.mark.asyncio
async def test_combined_raw_output_cap_keeps_a_prefix(python_tool):
    result = await python_tool(
        "import os; os.write(1,b'A'*4000); os.write(2,b'B'*1000000)",
        max_output_bytes=4097, timeout=3,
    )
    assert len(result.stdout.encode()) + len(result.stderr.encode()) == 4097
    assert set(result.stdout) <= {"A"} and set(result.stderr) <= {"B"}
    assert result.error == "output_limit_exceeded" and result.truncated
    assert result.cleanup_confirmed


@pytest.mark.asyncio
async def test_exact_cap_is_not_truncation(python_tool):
    result = await python_tool(
        "import os; os.write(1,b'A'*100); os.write(2,b'B'*40)",
        max_output_bytes=140, timeout=3,
    )
    assert result.stdout == "A" * 100 and result.stderr == "B" * 40
    assert result.error is None and result.exit_code == 0 and not result.truncated
    assert result.cleanup_confirmed


@pytest.mark.asyncio
async def test_output_limit_counts_bytes_before_utf8_replacement(python_tool):
    result = await python_tool(
        "import os; os.write(1,bytes([255])*42)", max_output_bytes=42, timeout=3,
    )
    assert result.stdout == "\ufffd" * 42
    assert result.error is None and not result.truncated


@pytest.mark.asyncio
async def test_timeout_retains_partial_output_and_reaps(python_tool):
    loop = asyncio.get_running_loop()
    start = loop.time()
    result = await python_tool(
        "import time; print('ready',flush=True); time.sleep(30)", timeout=1,
    )
    assert result.error and result.error.startswith("timed out after")
    assert result.stdout == "ready\n" and result.exit_code is not None
    assert result.cleanup_confirmed and not result.truncated
    assert loop.time() - start < 4.5


@pytest.mark.asyncio
async def test_deadline_includes_startup_and_late_handle_is_reaped(python_tool, monkeypatch):
    real_spawn = asyncio.create_subprocess_exec
    acquired, release = asyncio.Event(), asyncio.Event()
    children = []

    async def delayed_spawn(*args, **kwargs):
        proc = await real_spawn(*args, **kwargs)
        children.append(proc)
        acquired.set()
        await release.wait()
        return proc

    monkeypatch.setattr(cli.asyncio, "create_subprocess_exec", delayed_spawn)
    task = asyncio.create_task(python_tool("import time; time.sleep(30)", timeout=0.02))
    try:
        await asyncio.wait_for(acquired.wait(), 3)
        await asyncio.sleep(0.04)
        # Timeout cannot discard the as-yet-unreturned subprocess handle.
        assert not task.done()
        release.set()
        result = await asyncio.wait_for(task, 3)
        assert result.error and result.error.startswith("timed out after")
        assert result.cleanup_confirmed and children[0].returncode is not None
    finally:
        release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        for proc in children:
            await _reap(proc)


@pytest.mark.asyncio
async def test_repeated_cancel_during_startup_preserves_ownership(python_tool, monkeypatch):
    real_spawn = asyncio.create_subprocess_exec
    acquired, release = asyncio.Event(), asyncio.Event()
    children = []
    acquisition_cancelled = []

    async def delayed_spawn(*args, **kwargs):
        proc = await real_spawn(*args, **kwargs)
        children.append(proc)
        acquired.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            acquisition_cancelled.append(True)
            raise
        return proc

    monkeypatch.setattr(cli.asyncio, "create_subprocess_exec", delayed_spawn)
    task = asyncio.create_task(python_tool("import time; time.sleep(30)", timeout=3))
    try:
        await asyncio.wait_for(acquired.wait(), 3)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not acquisition_cancelled
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert children[0].returncode is not None and not acquisition_cancelled
    finally:
        release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        for proc in children:
            await _reap(proc)


@pytest.mark.asyncio
async def test_repeated_cancel_cannot_interrupt_kill_drain_cleanup(python_tool, monkeypatch):
    real_cleanup = cli._cleanup_process
    entered, release = asyncio.Event(), asyncio.Event()
    interrupted, children = [], []

    async def delayed_cleanup(proc, tasks):
        children.append(proc)
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            interrupted.append(True)
            raise
        return await real_cleanup(proc, tasks)

    monkeypatch.setattr(cli, "_cleanup_process", delayed_cleanup)
    task = asyncio.create_task(python_tool("import time; time.sleep(30)", timeout=0.05))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not interrupted
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert not interrupted and children[0].returncode is not None
    finally:
        release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        for proc in children:
            await _reap(proc)


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "linux", reason="Linux fork/process-state assertion")
async def test_descendant_pipe_holder_is_killed_after_parent_exit(python_tool):
    result = await python_tool(
        "import os,time; pid=os.fork(); "
        "time.sleep(30) if pid==0 else (print(pid,flush=True),os._exit(0))",
        timeout=1,
    )
    assert result.error and result.error.startswith("timed out after")
    assert result.cleanup_confirmed and result.exit_code == 0
    pid = int(result.stdout.strip())
    status = Path(f"/proc/{pid}/stat")
    try:
        # A grandchild can be an init-owned zombie before CI's init reaps it;
        # either absence or Z confirms it can no longer run or hold pipes.
        assert not status.exists() or status.read_text().split()[2] == "Z"
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


@pytest.mark.asyncio
async def test_unconfirmed_cleanup_closes_transport_within_reserve():
    class Transport:
        closed = False

        def close(self):
            self.closed = True

    class Process:
        pid = 2147483647  # Outside supported OS PID ranges; never a real group.
        returncode = None
        stdin = None
        stdout = asyncio.StreamReader()
        stderr = asyncio.StreamReader()
        _transport = Transport()

        def kill(self):
            pass

        async def wait(self):
            await asyncio.Event().wait()

    proc = Process()
    assert await asyncio.wait_for(cli._cleanup_process(proc, []), 3) is False
    assert proc._transport.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs,error", [
    ({}, "scope_required"),
    ({"targets": [_TARGET]}, "scope_required"),
    ({"scope_check": lambda _t: True}, "scope_required"),
    ({"targets": [_TARGET], "scope_check": lambda _t: False}, "out_of_scope"),
    ({"targets": [" "], "scope_check": lambda _t: True}, "out_of_scope"),
])
async def test_scope_rejection_precedes_lookup_and_spawn(monkeypatch, kwargs, error):
    def forbidden_lookup(_tool):
        raise AssertionError("scope rejection must precede lookup")
    spawn = AsyncMock(side_effect=AssertionError("scope rejection must precede spawn"))
    monkeypatch.setattr(cli, "tool_path", forbidden_lookup)
    monkeypatch.setattr(cli.asyncio, "create_subprocess_exec", spawn)
    result = await cli.run_tool("httpx", [], **kwargs)
    assert result.error == error and not result.available
    spawn.assert_not_awaited()


@pytest.mark.asyncio
async def test_scope_callback_exception_fails_closed(monkeypatch):
    def bad_scope(_target):
        raise RuntimeError("unavailable")
    monkeypatch.setattr(cli, "tool_path", lambda _t: pytest.fail("unexpected lookup"))
    result = await cli.run_tool("httpx", [], targets=[_TARGET], scope_check=bad_scope)
    assert result.error == "out_of_scope"


@pytest.mark.asyncio
async def test_unknown_and_disabled_legacy_order(monkeypatch):
    monkeypatch.setattr(cli, "tool_path", lambda _t: pytest.fail("unexpected lookup"))
    disabled = await cli.run_tool("not-a-tool", [], allow=False)
    assert "disabled" in disabled.error and not disabled.available
    unknown = await cli.run_tool(sys.executable, [])
    assert unknown.error == "unknown_tool" and not unknown.available


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [True, False, 0, -1, float("nan"), float("inf"), 10**1000])
async def test_invalid_timeout_rejected_before_lookup(monkeypatch, value):
    monkeypatch.setattr(cli, "tool_path", lambda _t: pytest.fail("unexpected lookup"))
    result = await cli.run_tool("httpx", [], timeout=value)
    assert result.error == "invalid_timeout"


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, 16 * 1024 * 1024 + 1])
async def test_invalid_output_limit_rejected_before_lookup(monkeypatch, value):
    monkeypatch.setattr(cli, "tool_path", lambda _t: pytest.fail("unexpected lookup"))
    result = await cli.run_tool("httpx", [], max_output_bytes=value)
    assert result.error == "invalid_output_limit"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["checksec", "ilspycmd"])
async def test_local_binary_categories_keep_legacy_invocation(python_tool, tool):
    result = await cli.run_tool(tool, ["-c", "print('local')"], timeout=3)
    assert result.stdout == "local\n" and result.error is None


@pytest.mark.asyncio
async def test_missing_binary_keeps_fallback_hint(monkeypatch):
    monkeypatch.setattr(cli, "tool_path", lambda _t: None)
    result = await cli.run_tool(
        "httpx", [], targets=[_TARGET], scope_check=lambda _t: True,
    )
    assert not result.available and "not installed" in result.error
    assert result.fallback == cli.KNOWN_TOOLS["httpx"].fallback


@pytest.mark.asyncio
async def test_start_failure_is_a_legacy_result(python_tool, monkeypatch):
    monkeypatch.setattr(cli.asyncio, "create_subprocess_exec",
                        AsyncMock(side_effect=OSError("spawn refused")))
    result = await python_tool("pass")
    assert result.available and result.error == "spawn refused"
    assert result.exit_code is None and result.cleanup_confirmed


@pytest.mark.parametrize("value", [
    "file:///etc/passwd", "file:/etc/passwd", "data:text/plain,private",
    "ftp://outside.example/x", "ftps:outside.example", "gopher:outside.example",
    "javascript:alert(1)", "ssh://outside.example", "FILE:/etc/passwd",
])
@pytest.mark.parametrize("inline", [False, True])
def test_non_http_uri_scanner_values_are_rejected(value, inline):
    arg = "--target=" + value if inline else value
    assert srv._reject_dangerous_scanner_args([arg]) is not None


@pytest.mark.parametrize("args", [
    ["-u", "https://example.test/path"],
    ["--target=https://example.test/path"],
    ["--target=http://example.test,https://other.test"],
])
def test_http_uri_scanner_values_remain_allowed(args):
    assert srv._reject_dangerous_scanner_args(args) is None


@pytest.mark.parametrize("arg", ["--target=/etc/passwd", "--value=../private",
                                 "--output=result.json", "--input-file=/tmp/input"])
def test_inline_filesystem_arguments_are_rejected(arg):
    assert srv._reject_dangerous_scanner_args([arg]) is not None


def test_inline_targets_are_extracted_before_list_splitting():
    assert srv._host_like_tokens([
        "--target=https://outside.example,https://127.0.0.1",
        "--ports=80,443", "--tags=redis,mongodb",
    ]) == ["https://outside.example", "https://127.0.0.1"]


@pytest.mark.asyncio
async def test_inline_out_of_scope_target_cannot_hide_behind_declared_target(
        fresh_context, monkeypatch):
    runner = AsyncMock()
    monkeypatch.setattr(cli, "run_tool", runner)
    result = await srv.run_scanner(
        "httpx", ["--target=https://outside.example"], target=_TARGET,
    )
    assert result["error"] == "out_of_scope"
    runner.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_scanner_passes_explicit_scope_to_python_runner(fresh_context, monkeypatch):
    runner = AsyncMock(return_value=cli.CliResult("httpx", True, exit_code=0))
    monkeypatch.setattr(cli, "run_tool", runner)
    result = await srv.run_scanner("httpx", ["--target=" + _TARGET])
    assert result.get("error") is None
    kwargs = runner.await_args.kwargs
    assert kwargs["targets"] == [_TARGET]
    assert kwargs["scope_check"](_TARGET) and not kwargs["scope_check"]("https://outside.example")


@pytest.mark.asyncio
async def test_disabled_scope_is_explicit_at_python_boundary(fresh_context, monkeypatch):
    fresh_context.settings = replace(fresh_context.settings, enforce_scope=False)
    runner = AsyncMock(return_value=cli.CliResult("httpx", True, exit_code=0))
    monkeypatch.setattr(cli, "run_tool", runner)
    await srv.run_scanner("httpx", ["-silent"])
    kwargs = runner.await_args.kwargs
    assert kwargs["targets"] == ["httpx"] and kwargs["scope_check"]("https://outside.example")


_ROW = json.dumps({
    "template-id": "fixture-only",
    "info": {"name": "Review lead", "severity": "info", "description": "local fixture"},
    "matched-at": _TARGET, "type": "http",
}) + "\n"


@pytest.mark.asyncio
@pytest.mark.parametrize("error,code,truncated,cleanup", [
    ("timed out after 1s", None, False, True),
    ("output_limit_exceeded", -9, True, True),
    (None, 2, False, True),
    (None, 0, True, True),
    (None, 0, False, False),
])
async def test_incomplete_vuln_scan_keeps_leads_without_recording(
        fresh_context, monkeypatch, error, code, truncated, cleanup):
    runner = AsyncMock(return_value=cli.CliResult(
        "nuclei", True, stdout=_ROW, error=error, exit_code=code,
        truncated=truncated, cleanup_confirmed=cleanup,
    ))
    monkeypatch.setattr(cli, "run_tool", runner)
    result = await srv.vuln_scan(_TARGET, record=True)
    assert result["ok"] is False and result["state"] == "partial"
    assert result["retryable"] is False and result["error"]
    assert result["finding_count"] == 1 and result["findings"][0]["template_id"] == "fixture-only"
    assert result["recorded"] == 0 and fresh_context.findings.list() == []
    assert outcome(result).state == "partial"
    kwargs = runner.await_args.kwargs
    assert kwargs["targets"] == [_TARGET] and kwargs["scope_check"](_TARGET)


@pytest.mark.asyncio
async def test_empty_incomplete_scan_is_unknown_not_clean(fresh_context, monkeypatch):
    monkeypatch.setattr(cli, "run_tool", AsyncMock(return_value=cli.CliResult(
        "nuclei", True, error="timed out after 1s",
    )))
    result = await srv.vuln_scan(_TARGET, record=True)
    assert result["ok"] is False and result["state"] == "unknown"
    assert result["finding_count"] == 0 and not result["retryable"]
    assert outcome(result).state == "unknown"


@pytest.mark.asyncio
async def test_successful_scan_keeps_recording_compatibility(fresh_context, monkeypatch):
    monkeypatch.setattr(cli, "run_tool", AsyncMock(return_value=cli.CliResult(
        "nuclei", True, exit_code=0, stdout="[]\n42\n" + _ROW,
    )))
    result = await srv.vuln_scan(_TARGET, record=True)
    assert result.get("error") is None and result["recorded"] == 1
    assert result["finding_count"] == 1 and len(fresh_context.findings.list()) == 1
    assert outcome(result).ok


@pytest.mark.asyncio
async def test_missing_nuclei_keeps_legacy_response(fresh_context, monkeypatch):
    monkeypatch.setattr(cli, "run_tool", AsyncMock(return_value=cli.CliResult(
        "nuclei", False, error="not installed",
    )))
    result = await srv.vuln_scan(_TARGET)
    assert result["error"] == "nuclei_unavailable" and result["also_run_native"]
