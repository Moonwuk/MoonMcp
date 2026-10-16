"""Real Docker + real HTTP + SQLite. Explicitly enabled in the research CI job."""
import asyncio
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from moonmcp import research
from moonmcp.research_runtime import ResearchSandbox, bounded_command
from moonmcp.runs import RunStore

pytestmark = pytest.mark.skipif(os.environ.get("MOONMCP_TEST_DOCKER") != "1",
                                reason="requires local Docker and the preloaded pinned recipe image")


@pytest.mark.parametrize("recipe_id", ["sqlite-orders-v1", "sqlite-notes-v1"])
@pytest.mark.parametrize("case", sorted(research.CASES))
async def test_real_http_replay_matches_independent_expected_case_and_cleans_up(tmp_path, case, recipe_id):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    result = await research.replay(store, research.capsule(case, recipe_id), execute=True)
    assert result["ok"], result
    assert result["evaluation"]["matched"]
    assert result["cleanup"]["ok"]
    assert result["metrics"]["prepare"]["requests"] >= 8
    assert result["metrics"]["verify"]["requests"] == (8 if case.startswith("private") else 0)
    assert {"runtime", "prepare", "verify", "cleanup"} == set(result["metrics"])
    assert result["elapsed_seconds"] > 0
    witness = next(a for a in store.artifacts(result["run_id"], include_content=True) if a["kind"] == "research_prepare")
    fidelity = json.loads(witness["content"])["fidelity"]
    assert fidelity["live_identities_checked"] and not fidelity["substitutions"]
    assert fidelity["session_revocation_checked"] == (recipe_id == "sqlite-notes-v1")
    run = store.get(result["run_id"])
    assert run["budget"]["requests"]["used"] == sum(p["requests"] for p in result["metrics"].values())
    assert run["state"] == "completed"
    record = json.loads(store.get_artifact(run["id"], result["resource"]["id"])["content"])
    box = ResearchSandbox(record, tmp_path / "research")
    assert not box.checked(["container", "ls", "-a", "--filter", f"label=moonmcp.research={record['id']}", "--format", "{{.ID}}"])
    assert not box.directory.exists()
    assert (await research.cleanup(store, run["id"], result["resource"]["id"]))["ok"]


@pytest.mark.parametrize("recipe_id", ["sqlite-orders-v1", "sqlite-notes-v1"])
async def test_portable_capsule_replays_into_a_new_store_with_new_identities(tmp_path, recipe_id):
    stores = [RunStore(str(tmp_path / part / "runs.sqlite")) for part in ("original", "independent")]
    first = await research.replay(stores[0], research.capsule("private_vulnerable", recipe_id), execute=True)
    assert first["ok"], first
    portable = json.loads(stores[0].get_artifact(first["run_id"], first["capsule_artifact"]["id"])["content"])
    assert not any(k in json.dumps(portable).lower() for k in ("password", "token", "127.0.0.1"))
    second = await research.replay(stores[1], portable, execute=True)
    assert second["ok"], second
    a, b = first["verification"]["proof"], second["verification"]["proof"]
    assert a["verified"] and b["verified"]
    assert a["resource"]["id"] != b["resource"]["id"]
    assert a["owner"] != b["owner"] and a["observer"] != b["observer"]


def test_real_runtime_has_no_egress_readonly_root_and_bounded_exec(tmp_path, monkeypatch):
    docker_config = tmp_path / "docker-config"
    docker_config.mkdir()
    (docker_config / "config.json").write_text(json.dumps({"proxies": {"default": {
        "httpProxy": "http://synthetic:credential@127.0.0.1:9",
        "httpsProxy": "http://synthetic:credential@127.0.0.1:9"}}}))
    monkeypatch.setenv("DOCKER_CONFIG", str(docker_config))
    ident = uuid.uuid4().hex
    record = {"id": ident, "container": "moonmcp-lab-" + ident, "variant": "fixed"}
    box = ResearchSandbox(record, tmp_path)
    try:
        assert box.start()["settings"]["network"] == "none"
        program = """import os,socket
assert os.getuid()==65532
assert not any(value for key,value in os.environ.items() if key.lower().endswith('_proxy'))
assert [name for _,name in socket.if_nameindex()]==['lo']
try:
 open('/unexpected','w')
except OSError: pass
else: raise AssertionError('writable root')
s=socket.socket(); s.settimeout(.2)
try:
 s.connect(('192.0.2.1',80))
except OSError: pass
else: raise AssertionError('IP egress available')
print('limits verified')
"""
        assert b"limits verified" in box.checked(["exec", record["container"], "python", "-c", program])
        with pytest.raises(RuntimeError, match="output limit"):
            bounded_command(["docker", "exec", record["container"], "python", "-c", "print('x'*100000)"])
    finally:
        assert ResearchSandbox(record, tmp_path).cleanup()["ok"]


@pytest.mark.parametrize("recipe_id", ["sqlite-orders-v1", "sqlite-notes-v1"])
async def test_hard_worker_loss_is_recovered_without_replaying_http(tmp_path, recipe_id):
    path = str(tmp_path / "runs.sqlite")
    script = """import asyncio,os,sys
from moonmcp import research
from moonmcp.research_runtime import ResearchSandbox
from moonmcp.runs import RunStore
start=ResearchSandbox.start
def crash(self):
 start(self)
 os._exit(17)
ResearchSandbox.start=crash
asyncio.run(research.replay(RunStore(sys.argv[1]), research.capsule('private_fixed', sys.argv[2]), execute=True))
"""
    worker = await asyncio.create_subprocess_exec(sys.executable, "-c", script, path, recipe_id,
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    await asyncio.wait_for(worker.communicate(), 60)
    assert worker.returncode == 17
    store = RunStore(path)
    run = store.list_runs()[0]
    artifact = next(a for a in store.artifacts(run["id"]) if a["kind"] == "research_resource")
    record = json.loads(store.get_artifact(run["id"], artifact["id"])["content"])
    try:
        with pytest.raises(ValueError, match="active lease"):
            await research.cleanup(store, run["id"], artifact["id"])
        store._db.execute("UPDATE tasks SET lease_until=0 WHERE run_id=?", (run["id"],))
        store._db.commit()
        result = await research.cleanup(store, run["id"], artifact["id"])
        assert result["ok"]
        assert store.tasks(run["id"])[0]["state"] == "blocked"
        assert store.get(run["id"])["budget"]["requests"]["used"] == 0
    finally:
        assert ResearchSandbox(record, Path(path).parent / "research").cleanup()["ok"]


async def test_invalid_internal_harness_cannot_establish_real_http_violation(tmp_path, monkeypatch):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    original = research.verify_private_read
    observation = {}

    async def compare(client, target, spec, **kwargs):
        run_id = store.list_runs()[0]["id"]
        artifact = next(a for a in store.artifacts(run_id, include_content=True) if a["kind"] == "research_resource")
        record = json.loads(artifact["content"])
        box = ResearchSandbox(record, tmp_path / "research")
        # Deliberately remove both middleware layers. This is a test-only
        # counterexample, never a route or recipe exposed by the MCP tool.
        program = """import hashlib,json,runpy,sys
module=runpy.run_path('/app.py')
status=[]
body=b''.join(module['Notes']('/tmp/notes.sqlite')(
 {'PATH_INFO':'/notes/'+sys.argv[1], 'REQUEST_METHOD':'GET'}, lambda s,h:status.append(s)))
print(json.dumps({'status':int(status[0].split()[0]),'body_sha256':hashlib.sha256(body).hexdigest()}))
"""
        data = await asyncio.to_thread(box.checked, ["exec", record["container"], "python", "-c", program, spec["resource"]["id"]])
        observation.update(json.loads(data))
        observation.update(entrypoint="direct_domain_handler", classification="harness_only",
                           substitutions=["session middleware removed", "object policy middleware removed"])
        store.add_artifact(run_id, "test_invalid_harness", "counterexample.json", json.dumps(observation))
        return await original(client, target, spec, **kwargs)

    monkeypatch.setattr(research, "verify_private_read", compare)
    result = await research.replay(store, research.capsule("private_fixed", "sqlite-notes-v1"), execute=True)
    assert result["ok"], result
    assert observation["status"] == 200
    checks = {c["check"]: c for c in result["verification"]["checks"]}
    assert observation["body_sha256"] == checks["owner_object"]["body_sha256"]
    assert checks["observer_object"]["status"] == 403
    assert not result["verification"]["proof"]["verified"]
    assert result["verification"]["verdict"] == "not_verified"
    assert result["cleanup"]["ok"]


async def test_revoked_cookie_leaves_incomplete_evidence_and_no_clean_negative(tmp_path, monkeypatch):
    from urllib.parse import urlsplit

    from moonmcp.net.http import HttpClient
    store = RunStore(str(tmp_path / "runs.sqlite"))
    fetch = HttpClient.fetch
    verify = research.verify_private_read
    latest_login = {}

    async def track(self, url, **kwargs):
        response = await fetch(self, url, **kwargs)
        if urlsplit(url).path == "/session" and response.status == 200:
            latest_login.update(json.loads(response.body))
        return response

    async def revoke(client, target, spec, **kwargs):
        parsed = urlsplit(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        revoked = await client.fetch(origin + "/session/logout", method="POST", headers={
            **kwargs["second_headers"], "X-CSRF-Token": latest_login["csrf"], "Origin": origin},
            timeout=5, suppress_auth=True)
        assert revoked.status == 200
        return await verify(client, target, spec, **kwargs)

    monkeypatch.setattr(HttpClient, "fetch", track)
    monkeypatch.setattr(research, "verify_private_read", revoke)
    result = await research.replay(store, research.capsule("private_vulnerable", "sqlite-notes-v1"), execute=True)
    assert not result["ok"] and result["state"] == "unknown"
    assert result["cleanup"]["ok"]
    artifact = next(a for a in store.artifacts(result["run_id"], include_content=True) if a["kind"] == "research_verify")
    evidence = json.loads(artifact["content"])
    assert evidence["verdict"] == "inconclusive" and not evidence["proof"]["verified"]
    assert any(c["check"] == "observer_identity_before" and c["status"] == 401 for c in evidence["checks"])
    assert store.tasks(result["run_id"])[0]["state"] == "blocked"
    for artifact in store.artifacts(result["run_id"], include_content=True):
        assert latest_login["csrf"] not in artifact["content"]
