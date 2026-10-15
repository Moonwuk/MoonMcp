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


@pytest.mark.parametrize("case", sorted(research.CASES))
async def test_real_http_replay_matches_independent_expected_case_and_cleans_up(tmp_path, case):
    store = RunStore(str(tmp_path / "runs.sqlite"))
    result = await research.replay(store, research.capsule(case), execute=True)
    assert result["ok"], result
    assert result["evaluation"]["matched"]
    assert result["cleanup"]["ok"]
    assert result["metrics"]["prepare"]["requests"] >= 8
    assert result["metrics"]["verify"]["requests"] == (8 if case.startswith("private") else 0)
    run = store.get(result["run_id"])
    assert run["budget"]["requests"]["used"] == sum(p["requests"] for p in result["metrics"].values())
    assert run["state"] == "completed"
    record = json.loads(store.get_artifact(run["id"], result["resource"]["id"])["content"])
    box = ResearchSandbox(record, tmp_path / "research")
    assert not box.checked(["container", "ls", "-a", "--filter", f"label=moonmcp.research={record['id']}", "--format", "{{.ID}}"])
    assert not box.directory.exists()
    assert (await research.cleanup(store, run["id"], result["resource"]["id"]))["ok"]


async def test_portable_capsule_replays_into_a_new_store_with_new_identities(tmp_path):
    stores = [RunStore(str(tmp_path / part / "runs.sqlite")) for part in ("original", "independent")]
    first = await research.replay(stores[0], research.capsule("private_vulnerable"), execute=True)
    assert first["ok"], first
    portable = json.loads(stores[0].get_artifact(first["run_id"], first["capsule_artifact"]["id"])["content"])
    assert not any(k in json.dumps(portable).lower() for k in ("password", "token", "127.0.0.1"))
    second = await research.replay(stores[1], portable, execute=True)
    assert second["ok"], second
    a, b = first["verification"]["proof"], second["verification"]["proof"]
    assert a["verified"] and b["verified"]
    assert a["resource"]["id"] != b["resource"]["id"]
    assert a["owner"] != b["owner"] and a["observer"] != b["observer"]


def test_real_runtime_has_no_egress_readonly_root_and_bounded_exec(tmp_path):
    ident = uuid.uuid4().hex
    record = {"id": ident, "container": "moonmcp-lab-" + ident, "variant": "fixed"}
    box = ResearchSandbox(record, tmp_path)
    try:
        assert box.start()["settings"]["network"] == "none"
        program = """import os,socket
assert os.getuid()==65532
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


async def test_hard_worker_loss_is_recovered_without_replaying_http(tmp_path):
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
asyncio.run(research.replay(RunStore(sys.argv[1]), research.capsule('private_fixed'), execute=True))
"""
    worker = await asyncio.create_subprocess_exec(sys.executable, "-c", script, path,
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
