"""Regression tests for the Strix MCP wrapper's process/temp-file lifecycle.

These pin the cleanup fixes from the adversarial review: the detached path must
not leak the instruction file, and a failed spawn must clean up + return an error
instead of leaking the temp file / log fd or crashing the run. No real Strix or
terminal is launched — the subprocess exec is faked.
"""

import asyncio
import os

import pytest

pytest.importorskip("mcp")

from examples.strix_mcp import server as sx  # noqa: E402


class _FakeProc:
    def __init__(self, rc: int = 0):
        self.returncode = rc
        self.pid = 4242

    async def wait(self) -> int:
        return self.returncode

    async def communicate(self):
        return (b"strix output", b"")


def _instr_path(calls: list) -> str:
    args = calls[-1]
    return args[args.index("--instruction-file") + 1]


@pytest.fixture
def strix_ready(monkeypatch):
    """strix present, LLM configured, target in scope — but nothing really runs."""
    monkeypatch.setattr(sx.shutil, "which",
                        lambda n: "/usr/bin/strix" if n == "strix" else None)
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setattr(sx, "_scope_check", lambda target: None)  # in scope


@pytest.mark.asyncio
async def test_detached_run_cleans_up_instruction_file(strix_ready, monkeypatch):
    calls: list = []

    async def fake_exec(*args, **kw):
        calls.append(list(args))
        return _FakeProc()

    monkeypatch.setattr(sx.asyncio, "create_subprocess_exec", fake_exec)

    res = await sx.strix_run(target="http://t.example", instruction="probe",
                             wait=False, watch=False)
    assert res["launched"] is True
    path = _instr_path(calls)
    # The detached child still needs the file, so it must exist right after return…
    assert os.path.exists(path)
    # …and be reaped once the (fake) child exits.
    for _ in range(20):
        await asyncio.sleep(0.01)
        if not os.path.exists(path):
            break
    assert not os.path.exists(path), "detached run leaked the instruction file"


@pytest.mark.asyncio
async def test_spawn_failure_cleans_up_and_returns_error(strix_ready, monkeypatch):
    calls: list = []

    async def boom_exec(*args, **kw):
        calls.append(list(args))
        raise OSError(24, "Too many open files")  # EMFILE

    monkeypatch.setattr(sx.asyncio, "create_subprocess_exec", boom_exec)

    res = await sx.strix_run(target="http://t.example", instruction="probe",
                             wait=True, watch=False)
    assert res["error"] == "spawn_failed"
    assert "OSError" in res["detail"]
    assert not os.path.exists(_instr_path(calls)), "failed spawn leaked the instruction file"


@pytest.mark.asyncio
async def test_wait_run_cleans_up_instruction_file(strix_ready, monkeypatch):
    calls: list = []

    async def fake_exec(*args, **kw):
        calls.append(list(args))
        return _FakeProc(rc=0)

    monkeypatch.setattr(sx.asyncio, "create_subprocess_exec", fake_exec)

    res = await sx.strix_run(target="http://t.example", instruction="probe",
                             wait=True, watch=False)
    assert res["target"] == "http://t.example"
    assert res["exit_code"] == 0
    assert not os.path.exists(_instr_path(calls)), "wait run leaked the instruction file"
