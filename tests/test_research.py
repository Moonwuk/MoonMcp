"""Admission, lifecycle faults and dispatch accounting without requiring Docker."""
import asyncio
import json
import subprocess
import sys
import threading
import uuid

import pytest

from moonmcp import research, research_runtime, server
from moonmcp.execution import ExecutionBlocked, execute_tool
from moonmcp.net.http import HttpClient
from moonmcp.net.ratelimit import Governor
from moonmcp.research_runtime import ResearchSandbox, bounded_command
from moonmcp.runs import RunStore


@pytest.mark.parametrize("change", [
    {"command": "echo ignored"}, {"image": "python:latest"}, {"version": True},
    {"entrypoint": "database"}, {"application_sha256": "0" * 64},
    {"case": "arbitrary-project"}, {"target": "https://example.org"},
])
async def test_capsule_rejects_unsupported_input_before_state_or_side_effects(tmp_path, change):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    with pytest.raises(ValueError):
        await research.replay(store, {**research.capsule("private_fixed"), **change}, execute=True)
    assert not store.list_runs()
    assert not (tmp_path / "research").exists()


async def test_preview_and_describe_require_no_runtime(monkeypatch):
    monkeypatch.setattr(ResearchSandbox, "start", lambda _: pytest.fail("unexpected start"))
    result = await server.research_environment()
    assert result["ok"] and len(result["capsules"]) == 4
    store = RunStore()
    result = await research.replay(store, result["capsules"][0])
    assert result["ok"] and not result["executed"] and not store.list_runs()
    with pytest.raises(ValueError, match="persistent"):
        await research.replay(store, research.capsule("private_fixed"), execute=True)


async def test_control_tool_cannot_be_nested_in_managed_run():
    with pytest.raises(ExecutionBlocked, match="control tools"):
        await execute_tool(None, {}, "unused", "research_environment", {})


def resource():
    ident = uuid.uuid4().hex
    return {"id": ident, "container": "moonmcp-lab-" + ident, "variant": "fixed"}


@pytest.mark.parametrize("failure", ["ownership", "daemon", "removal"])
def test_cleanup_never_calls_unknown_resource_absent(tmp_path, monkeypatch, failure):
    box = ResearchSandbox(resource(), tmp_path)
    def command(args, **kw):
        if failure == "daemon":
            raise subprocess.TimeoutExpired(args, 30)
        if "label=" in " ".join(args) and failure == "ownership":
            return b""
        return b"a" * 64
    monkeypatch.setattr(box, "checked", command)
    stopped = []
    monkeypatch.setattr(box, "stop", lambda: stopped.append(True))
    result = box.cleanup()
    assert not result["ok"] and result["state"] == "unknown"
    assert bool(stopped) == (failure == "removal")


def test_cleanup_refuses_unexpected_host_files(tmp_path, monkeypatch):
    box = ResearchSandbox(resource(), tmp_path)
    box.directory.mkdir()
    (box.directory / "unexpected").write_text("preserve")
    monkeypatch.setattr(box, "checked", lambda *a, **kw: b"")
    monkeypatch.setattr(box, "stop", lambda: {})
    assert box.cleanup()["remaining"] == ["socket_cleanup_unconfirmed"]
    assert (box.directory / "unexpected").read_text() == "preserve"


@pytest.mark.parametrize("script,expected", [
    ("import sys; sys.stderr.write('x'*100000); sys.stderr.flush()", RuntimeError),
    ("import time; time.sleep(30)", subprocess.TimeoutExpired),
])
def test_cli_output_and_deadline_are_bounded_and_worker_reaped(monkeypatch, script, expected):
    popen = subprocess.Popen
    workers = []
    def spawn(command, **kw):
        assert command[1] == "--host=unix:///var/run/docker.sock"
        assert "DOCKER_HOST" not in kw["env"]
        worker = popen([sys.executable, "-c", script], **kw)
        workers.append(worker)
        return worker
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted.invalid:2375")
    monkeypatch.setattr(subprocess, "Popen", spawn)
    with pytest.raises(expected):
        bounded_command(["docker", "inspect"], timeout=.3, limit=1000)
    assert workers[0].poll() is not None


async def test_intent_precedes_start_and_lost_result_stays_unknown(tmp_path, monkeypatch):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    observed = []
    def start(box):
        artifacts = store.artifacts(store.list_runs()[0]["id"], include_content=True)
        record = next(a for a in artifacts if a["kind"] == "research_resource")
        assert json.loads(record["content"])["container"] == box.resource["container"]
        observed.append("started")
        raise subprocess.TimeoutExpired("docker run", 45)
    def cleanup(box):
        observed.append("cleanup")
        assert not box.cancelled.is_set()  # separate cleanup budget/cancellation token
        return {"ok": False, "state": "unknown", "remaining": ["container"]}
    monkeypatch.setattr(ResearchSandbox, "start", start)
    monkeypatch.setattr(ResearchSandbox, "cleanup", cleanup)
    result = await research.replay(store, research.capsule("private_fixed"), execute=True)
    assert observed == ["started", "cleanup"]
    assert not result["ok"] and result["error"] == "cleanup_unconfirmed"
    assert store.tasks(result["run_id"])[0]["state"] == "blocked"
    assert any(a["kind"] == "research_cleanup" for a in store.artifacts(result["run_id"]))


async def test_cancel_waits_for_start_thread_before_cleanup(tmp_path, monkeypatch):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    entered, release = threading.Event(), threading.Event()
    observed = []
    def start(box):
        entered.set()
        assert release.wait(5)
        observed.append("start_settled")
        return {}
    def cleanup(box):
        observed.append("cleanup")
        return {"ok": True, "state": "completed"}
    monkeypatch.setattr(ResearchSandbox, "start", start)
    monkeypatch.setattr(ResearchSandbox, "cleanup", cleanup)
    worker = asyncio.create_task(research.replay(store, research.capsule("private_fixed"), execute=True))
    assert await asyncio.to_thread(entered.wait, 5)
    worker.cancel()
    await asyncio.sleep(.05)
    assert not worker.done() and not observed
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await worker
    assert observed == ["start_settled", "cleanup"]
    run = store.list_runs()[0]
    assert store.tasks(run["id"])[0]["state"] == "blocked"


async def test_recovery_requires_expired_lease_and_released_host_lock(tmp_path, monkeypatch):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    run = store.create("127.0.0.1")
    task = store.add_task(run["id"], "test")
    store.claim_task(run["id"], "worker", task_id=task["id"])
    record = {**resource(), "version": 1, "task_id": task["id"], "recipe": research.RECIPE}
    ref = research._artifact(store, run["id"], "research_resource", record)
    with pytest.raises(ValueError, match="active lease"):
        await research.cleanup(store, run["id"], ref["id"])
    store._db.execute("UPDATE tasks SET lease_until=0 WHERE id=?", (task["id"],))
    store._db.commit()
    with research._exclusive(tmp_path / "research"):
        with pytest.raises(ValueError, match="controller is active"):
            await research.cleanup(store, run["id"], ref["id"])
    monkeypatch.setattr(ResearchSandbox, "cleanup", lambda _: {"ok": True, "state": "completed"})
    assert (await research.cleanup(store, run["id"], ref["id"]))["ok"]
    assert store.task(task["id"])["state"] == "blocked"  # cleanup cannot assert an assessment passed


async def test_request_admission_blocks_transport_at_exhaustion(local_server, monkeypatch):
    base, _ = local_server
    store = RunStore()
    from moonmcp.runs import RunBudget
    run = store.create("127.0.0.1", budget=RunBudget(max_requests=1))
    invocation = store.begin_invocation(run["id"], "recipe-test", "hash")
    client = HttpClient(Governor(rate=0, max_concurrency=1), user_agent="test",
                        before_send=lambda url: store.consume_invocation_request(invocation["id"]))
    assert (await client.fetch(base)).status == 200
    import moonmcp.net.http as http
    monkeypatch.setattr(http, "_blocking_fetch", lambda *a: pytest.fail("unbudgeted send"))
    with pytest.raises(ValueError, match="budget"):
        await client.fetch(base)
    assert store.get_invocation(invocation["id"])["requests_used"] == 1


def test_socket_relay_is_only_loopback(tmp_path):
    relay = research_runtime.HTTPRelay(tmp_path / "unused.sock")
    try:
        assert relay.server.server_address[0] == "127.0.0.1"
    finally:
        relay.close()


async def test_local_recipe_transport_ignores_ambient_proxy_and_impersonation(local_server, monkeypatch):
    import moonmcp.net.http as http
    base, _ = local_server
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(key, "http://127.0.0.1:1")
    for key in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(key, "")
    monkeypatch.setattr(http, "_USE_CURL_CFFI", True)
    monkeypatch.setattr(http, "_curl_cffi_fetch", lambda *a: pytest.fail("ambient transport selected"))
    client = HttpClient(Governor(rate=0, max_concurrency=1), user_agent="recipe", direct=True,
                        connect_pin=lambda host: (None, "127.0.0.1"))
    assert (await client.fetch(base)).status == 200


async def test_cancellation_during_cleanup_is_persisted_before_it_propagates(tmp_path, monkeypatch):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    entered, release = threading.Event(), threading.Event()
    def start(box):
        raise RuntimeError("startup failed")
    def cleanup(box):
        entered.set()
        assert release.wait(5)
        return {"ok": True, "state": "completed"}
    monkeypatch.setattr(ResearchSandbox, "start", start)
    monkeypatch.setattr(ResearchSandbox, "cleanup", cleanup)
    worker = asyncio.create_task(research.replay(store, research.capsule("private_fixed"), execute=True))
    assert await asyncio.to_thread(entered.wait, 5)
    worker.cancel()
    await asyncio.sleep(.05)
    assert not worker.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await worker
    run = store.list_runs()[0]
    artifacts = store.artifacts(run["id"], include_content=True)
    assert any(a["kind"] == "research_cleanup" and json.loads(a["content"])["ok"] for a in artifacts)
    assert store.tasks(run["id"])[0]["state"] == "blocked"


async def test_cleanup_does_not_turn_lost_lease_into_completed_assessment(tmp_path, monkeypatch):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    def start(box):
        raise RuntimeError("interrupted start")
    def cleanup(box):
        store._db.execute("UPDATE tasks SET lease_until=0")
        store._db.commit()
        return {"ok": True, "state": "completed"}
    monkeypatch.setattr(ResearchSandbox, "start", start)
    monkeypatch.setattr(ResearchSandbox, "cleanup", cleanup)
    result = await research.replay(store, research.capsule("private_fixed"), execute=True)
    assert result["cleanup"]["ok"]
    assert not result["ok"] and result["error"] == "research_lease_lost"
    assert store.tasks(result["run_id"])[0]["state"] == "blocked"
