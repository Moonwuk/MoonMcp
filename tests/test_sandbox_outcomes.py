"""Mock the Docker CLI; failure must retain the resource for reconciliation."""

import subprocess
from types import SimpleNamespace

import pytest

from moonmcp import server
from moonmcp.outcomes import RESULT_META, outcome
from moonmcp.strix_adapted import DockerSandbox


@pytest.fixture
def sandbox(monkeypatch):
    instance = DockerSandbox()
    instance._container_id = "fixture-container"
    monkeypatch.setattr(server, "_sandbox", instance)
    return instance


async def test_nonzero_process_is_a_protocol_failure(monkeypatch, sandbox):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=1, stdout=b"", stderr=b"fixture failed"))
    result = await server.mcp.call_tool("sandbox_exec", {"action": "exec", "command": "false"})
    assert result.isError and result.meta[RESULT_META]["state"] == "failed"
    assert result.structuredContent["exit_code"] == 1
    assert result.structuredContent["error"] == "command_failed"


@pytest.mark.parametrize("timeout", [False, True])
async def test_failed_cleanup_retains_server_and_container(monkeypatch, sandbox, timeout):
    def run(*args, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired("docker rm", 30)
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"daemon unavailable")
    monkeypatch.setattr(subprocess, "run", run)
    result = await server.sandbox_exec(action="stop")
    assert not outcome(result).ok
    assert result["error"] == "cleanup_failed"
    assert server._sandbox is sandbox
    assert sandbox._container_id == "fixture-container"
    assert (await server.sandbox_exec(action="start"))["error"] == "sandbox_exists"


async def test_confirmed_removal_releases_server_reference(monkeypatch, sandbox):
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=b"fixture-container", stderr=b"")
    monkeypatch.setattr(subprocess, "run", run)
    assert (await server.sandbox_exec(action="stop"))["success"]
    assert server._sandbox is None
    assert sandbox._container_id is None
    assert calls == [["docker", "rm", "-f", "fixture-container"]]


@pytest.mark.parametrize("timeout", [False, True])
@pytest.mark.parametrize("cid,selector", [("fixture-container", "name=^/fixture\\-container$"),
                                        ("a" * 64, "id=" + "a" * 64)])
async def test_confirmed_absence_reconciles_lost_cleanup(monkeypatch, sandbox, timeout, cid, selector):
    sandbox._container_id = cid
    sandbox._execution_unknown = True
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "rm":
            if timeout:
                raise subprocess.TimeoutExpired(args, 30)
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"No such container")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
    monkeypatch.setattr(subprocess, "run", run)
    assert (await server.sandbox_exec(action="stop"))["success"]
    assert calls[-1] == ["docker", "container", "ls", "--all", "--quiet", "--no-trunc",
                         "--filter", selector]
    assert server._sandbox is None and sandbox._container_id is None
    assert not sandbox._execution_unknown


@pytest.mark.parametrize("returncode,stdout", [(1, b""), (0, b"still-present\n")])
async def test_absence_requires_successful_empty_daemon_query(monkeypatch, sandbox, returncode, stdout):
    def run(args, **kwargs):
        if args[1] == "rm":
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"No such container")
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=b"daemon unavailable")
    monkeypatch.setattr(subprocess, "run", run)
    result = await server.sandbox_exec(action="stop")
    assert result["error"] == "cleanup_failed"
    assert server._sandbox is sandbox and sandbox._container_id == "fixture-container"


async def test_failed_start_with_no_created_container_can_be_restarted(monkeypatch):
    monkeypatch.setattr(server, "_sandbox", None)
    monkeypatch.setattr(DockerSandbox, "_check_docker", lambda self: True)
    fail_start = True
    def run(args, **kwargs):
        if args[1] == "run":
            return SimpleNamespace(returncode=1 if fail_start else 0,
                                   stdout=b"" if fail_start else b"a" * 64,
                                   stderr=b"start failed" if fail_start else b"")
        if args[1] == "rm":
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"No such container")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
    monkeypatch.setattr(subprocess, "run", run)
    assert (await server.sandbox_exec(action="start"))["error"] == "sandbox_start_failed"
    assert (await server.sandbox_exec(action="stop"))["success"]
    fail_start = False
    assert (await server.sandbox_exec(action="start"))["success"]


def test_timeout_quarantines_execution_until_cleanup(monkeypatch, sandbox):
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        raise subprocess.TimeoutExpired("docker exec", 1)
    monkeypatch.setattr(subprocess, "run", run)
    result = sandbox.exec("sleep 10", timeout=1)
    assert outcome(result).state == "unknown"
    assert not result["retryable"]
    assert outcome(sandbox.exec("echo later")).state == "unknown"
    assert len(calls) == 1


def test_default_start_has_no_network_extra_caps_or_host_gateway(monkeypatch):
    instance = DockerSandbox(cap_add=[])
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=b"fixture-container", stderr=b"")
    monkeypatch.setattr(instance, "_check_docker", lambda: True)
    monkeypatch.setattr(subprocess, "run", run)
    assert instance.start()["success"]
    command = calls[-1]
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "--cap-add" not in command and "--add-host" not in command
    assert instance.start()["error"] == "sandbox_exists"
    assert len(calls) == 2


async def test_lost_start_result_keeps_named_container_for_cleanup(monkeypatch):
    monkeypatch.setattr(server, "_sandbox", None)
    monkeypatch.setattr(DockerSandbox, "_check_docker", lambda self: True)
    def run(args, **kwargs):
        if args[1] == "run":
            raise subprocess.TimeoutExpired(args, 60)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
    monkeypatch.setattr(subprocess, "run", run)
    result = await server.sandbox_exec(action="start")
    assert outcome(result).state == "unknown"
    assert server._sandbox._container_id.startswith("moonmcp-sandbox-")
    assert outcome(server._sandbox.exec("echo unsafe-to-repeat")).state == "unknown"
    assert (await server.sandbox_exec(action="stop"))["success"]
