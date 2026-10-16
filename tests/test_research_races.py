"""Resource replacement and finalization races use independent runtime state."""

import json
import socket
import subprocess
import sys
import uuid

import pytest

from moonmcp import research
from moonmcp.research_runtime import ResearchSandbox
from moonmcp.runs import RunStore


def sandbox(tmp_path):
    ident = uuid.uuid4().hex
    return ResearchSandbox({"id": ident, "container": "moonmcp-lab-" + ident,
                            "variant": "fixed"}, tmp_path)


@pytest.mark.parametrize("replace", [False, True])
def test_cleanup_removes_verified_id_when_container_name_is_reused(tmp_path, monkeypatch, replace):
    box = sandbox(tmp_path)
    original, replacement = b"a" * 64, b"b" * 64
    box.directory.mkdir()
    live = {original, replacement}
    named = original
    removed = []

    def command(args, **kwargs):
        nonlocal named
        assert "--no-trunc" in args
        if any(arg.startswith("id=") for arg in args):
            ident = next(arg[3:].encode() for arg in args if arg.startswith("id="))
            return ident if ident in live else b""
        if any(arg.startswith("label=") for arg in args):
            # Both successful queries observed the original owned container.
            # Simulate external removal/name reuse immediately afterwards.
            named = replacement if replace else b""
            live.discard(original)
            return original
        return named

    def remove(args, **kwargs):
        assert args[:3] == ["docker", "rm", "-f"]
        removed.append(args[3].encode())
        live.discard(args[3].encode())
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(box, "checked", command)
    monkeypatch.setattr(box, "_run", remove)
    result = box.cleanup()
    assert removed == [original]
    assert replacement in live
    assert result["ok"] is not replace
    if replace:
        assert result["remaining"] == ["container_replaced"]
        assert box.directory.exists()
    else:
        assert not box.directory.exists()


def test_cleanup_proves_id_absent_even_when_original_container_was_renamed(tmp_path, monkeypatch):
    box = sandbox(tmp_path)
    original = b"a" * 64
    calls = 0

    def command(args, **kwargs):
        nonlocal calls
        calls += 1
        return original if calls <= 2 or f"id={original.decode()}" in args else b""

    monkeypatch.setattr(box, "checked", command)
    monkeypatch.setattr(box, "_run", lambda args, **kw: subprocess.CompletedProcess(args, 1, b"", b"failure"))
    result = box.cleanup()
    assert result["state"] == "unknown"
    assert result["remaining"] == ["container_still_exists"]


@pytest.mark.parametrize("reported_id", [b"abc123", b"a" * 64 + b"\n" + b"b" * 64])
def test_cleanup_refuses_truncated_or_multiple_ids(tmp_path, monkeypatch, reported_id):
    box = sandbox(tmp_path)
    monkeypatch.setattr(box, "checked", lambda *args, **kw: reported_id)
    monkeypatch.setattr(box, "stop", lambda: pytest.fail("unverified deletion"))
    assert box.cleanup()["remaining"] == ["container_identity_unconfirmed"]


def test_cleanup_does_not_remove_by_name_after_observing_absence(tmp_path, monkeypatch):
    box = sandbox(tmp_path)
    observed = iter([b"", b"", b"b" * 64])
    monkeypatch.setattr(box, "checked", lambda *args, **kw: next(observed))
    monkeypatch.setattr(box, "stop", lambda: pytest.fail("name-based deletion after absence"))
    assert box.cleanup()["remaining"] == ["container_replaced"]


@pytest.fixture
def native_recipe(monkeypatch):
    """Substitute Docker/Unix transport; retain real HTTP/SQLite and run state."""
    processes = []
    origins = {}

    def start(box):
        box.directory.mkdir(parents=True)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([
            sys.executable, "-I", str(research.recipe(research.RECIPE).app), "--variant", box.resource["variant"],
            "--database", "orders.sqlite", "--port", str(port),
        ], cwd=box.directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)
        origins[box.directory] = f"http://127.0.0.1:{port}"
        return {"test_runtime": "native SQLite fixture"}

    class Relay:
        def __init__(self, socket_path):
            self.base_url = origins[socket_path.parent]

        def close(self):
            pass

    def cleanup(box):
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        return {"ok": True, "state": "completed"}

    monkeypatch.setattr(ResearchSandbox, "start", start)
    monkeypatch.setattr(ResearchSandbox, "cleanup", cleanup)
    monkeypatch.setattr(research, "HTTPRelay", Relay)
    try:
        yield
    finally:
        cleanup(None)


@pytest.mark.parametrize("boundary", ["update_task", "finish"])
async def test_external_cancellation_at_finalization_is_unknown(tmp_path, monkeypatch, native_recipe, boundary):
    path = str(tmp_path / "runs.sqlite")
    store, external = RunStore(path), RunStore(path)
    original = getattr(store, boundary)

    def cancel(*args, **kwargs):
        run_id = store.task(args[0])["run_id"] if boundary == "update_task" else args[0]
        external.set_state(run_id, "cancelled")
        return original(*args, **kwargs)

    monkeypatch.setattr(store, boundary, cancel)
    try:
        result = await research.replay(store, research.capsule("private_fixed"), execute=True)
        assert result["evaluation"]["matched"]  # reproduction reached the success boundary
        assert result["cleanup"]["ok"]
        assert not result["ok"] and result["state"] == "unknown"
        assert result["error"] == "research_lease_lost"
        assert store.get(result["run_id"])["state"] == "cancelled"
        summaries = [json.loads(a["content"]) for a in external.artifacts(
            result["run_id"], include_content=True) if a["kind"] == "research_result"]
        assert len(summaries) == 1
        assert all(not value["ok"] and value["state"] == "unknown" for value in summaries)
        final = external.get_artifact(result["run_id"], result["result_artifact"]["id"])
        assert json.loads(final["content"]) == {k: v for k, v in result.items() if k != "result_artifact"}
    finally:
        store.close()
        external.close()


@pytest.mark.parametrize("blocked", [False, True])
async def test_authoritative_result_requires_run_completion(tmp_path, monkeypatch, native_recipe, blocked):
    path = str(tmp_path / "runs.sqlite")
    store, external = RunStore(path), RunStore(path)
    finish = store.finish

    def finish_with_blocker(run_id):
        external.add_task(run_id, "Concurrent unfinished work")
        return finish(run_id)

    if blocked:
        monkeypatch.setattr(store, "finish", finish_with_blocker)
    try:
        result = await research.replay(store, research.capsule("private_fixed"), execute=True)
        assert result["evaluation"]["matched"]
        assert result["ok"] is not blocked
        assert result["state"] == ("unknown" if blocked else "completed")
        assert store.get(result["run_id"])["state"] == ("running" if blocked else "completed")
        if blocked:
            assert result["error"] == "research_finalization_incomplete"
            assert result["blockers"] == ["1 unfinished task(s)"]
        final = json.loads(external.get_artifact(
            result["run_id"], result["result_artifact"]["id"])["content"])
        assert final["ok"] is not blocked
        pending = external.get_artifact(result["run_id"], result["finalization_artifact"]["id"])
        assert not json.loads(pending["content"])["ok"]
        assert store.tasks(result["run_id"])[0]["result"] == pending["uri"]
    finally:
        store.close()
        external.close()
