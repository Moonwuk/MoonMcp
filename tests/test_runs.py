"""Persistent assessment lifecycle, coordination, budgets and finish gates."""

import pytest

from moonmcp import server as srv
from moonmcp.runs import RunBudget, RunStore, seed_assessment


def test_run_persists_and_resumes(tmp_path):
    path = str(tmp_path / "runs.db")
    first = RunStore(path)
    run = first.create("example.test", focus="auth", budget=RunBudget(12, 7, 2))
    task = first.add_task(run["id"], "Map login", role="mapper", priority=80)
    first.set_coverage(run["id"], "auth", "in_progress", evidence="task:1")
    first.consume(run["id"], requests=3, tool_calls=1)

    resumed = RunStore(path)
    loaded = resumed.get(run["id"])
    assert loaded["target"] == "example.test"
    assert loaded["focus"] == "auth"
    assert loaded["budget"]["requests"] == {"used": 3, "max": 12}
    assert resumed.task(task["id"])["title"] == "Map login"
    assert loaded["coverage"]["counts"] == {"in_progress": 1}
    first.close()
    resumed.close()


def test_task_dependencies_and_next_task():
    store = RunStore()
    run = store.create("example.test")
    parent = store.add_task(run["id"], "First", priority=10)
    child = store.add_task(run["id"], "Second", priority=100, depends_on=parent["id"])
    assert store.next_task(run["id"])["id"] == parent["id"]
    store.update_task(parent["id"], "completed", result="done")
    assert store.next_task(run["id"])["id"] == child["id"]


def test_dependency_must_be_in_same_run():
    store = RunStore()
    one = store.create("one.test")
    two = store.create("two.test")
    parent = store.add_task(one["id"], "First")
    with pytest.raises(ValueError, match="same run"):
        store.add_task(two["id"], "Wrong", depends_on=parent["id"])


def test_budgets_are_atomic_and_cannot_be_exceeded():
    store = RunStore()
    run = store.create("example.test", budget=RunBudget(2, 1, 0))
    store.consume(run["id"], requests=2, tool_calls=1)
    with pytest.raises(ValueError, match="budget exceeded: requests"):
        store.consume(run["id"], requests=1)
    assert store.get(run["id"])["budget"]["requests"]["used"] == 2
    with pytest.raises(ValueError, match="non-negative"):
        store.consume(run["id"], requests=-1)


def test_budget_rejection_releases_database_for_other_sessions(tmp_path):
    path = str(tmp_path / "runs.db")
    first = RunStore(path)
    second = RunStore(path)
    second._db.execute("PRAGMA busy_timeout=0")
    try:
        run = first.create("example.test", budget=RunBudget(1, 1, 0))
        first.consume(run["id"], requests=1)
        with pytest.raises(ValueError, match="budget exceeded: requests"):
            first.consume(run["id"], requests=1)

        # A rejected increment must not retain SQLite's database-wide write lock.
        second.consume(run["id"], tool_calls=1)
        budget = second.get(run["id"])["budget"]
        assert budget["requests"]["used"] == 1
        assert budget["tool_calls"]["used"] == 1
        assert len(second.events(run["id"])) == 3
    finally:
        first.close()
        second.close()


def test_usage_event_failure_rolls_back_counters_and_releases_lock(tmp_path, monkeypatch):
    path = str(tmp_path / "runs.db")
    first = RunStore(path)
    second = RunStore(path)
    second._db.execute("PRAGMA busy_timeout=0")
    try:
        run = first.create("example.test", budget=RunBudget(1, 1, 0))

        def fail_event(*args):
            raise RuntimeError("event write failed")

        monkeypatch.setattr(first, "_event", fail_event)
        with pytest.raises(RuntimeError, match="event write failed"):
            first.consume(run["id"], requests=1)

        assert first.get(run["id"])["budget"]["requests"]["used"] == 0
        second.consume(run["id"], requests=1)
        assert len(second.events(run["id"])) == 2
    finally:
        first.close()
        second.close()


def test_finish_gate_requires_tasks_and_coverage():
    store = RunStore()
    run = store.create("example.test")
    task = store.add_task(run["id"], "Map")
    store.set_coverage(run["id"], "surface", "open")
    blocked = store.finish(run["id"])
    assert blocked["completed"] is False
    assert len(blocked["blockers"]) == 2

    store.update_task(task["id"], "completed")
    store.set_coverage(run["id"], "surface", "covered", evidence="exchange:1")
    complete = store.finish(run["id"])
    assert complete["completed"] is True
    assert complete["run"]["state"] == "completed"


def test_seed_assessment_creates_role_graph_and_coverage():
    store = RunStore()
    run = store.create("example.test")
    tasks = seed_assessment(store, run["id"])
    assert [task["role"] for task in tasks] == [
        "coordinator", "mapper", "hypothesis", "validator", "reporter",
    ]
    assert store.next_task(run["id"])["role"] == "coordinator"
    assert store.get(run["id"])["coverage"]["total"] == 7


def test_artifacts_are_digest_addressed_and_bounded():
    store = RunStore()
    run = store.create("example.test")
    artifact = store.add_artifact(run["id"], "http", "response.txt", "hello")
    assert len(artifact["sha256"]) == 64
    assert "content" not in store.artifacts(run["id"])[0]
    assert store.artifacts(run["id"], include_content=True)[0]["content"] == "hello"
    with pytest.raises(ValueError, match="1 MB"):
        store.add_artifact(run["id"], "blob", "huge", "x" * 1_000_001)


@pytest.mark.asyncio
async def test_mcp_run_lifecycle_requires_scope(fresh_context):
    denied = await srv.run_start("example.test")
    assert denied["error"] == "out_of_scope"

    fresh_context.scope.add("example.test")
    started = await srv.run_start("example.test", max_requests=5)
    run_id = started["run"]["id"]
    assert started["next"]["role"] == "coordinator"

    paused = await srv.run_control(run_id, "pause")
    assert paused["run"]["state"] == "paused"
    assert (await srv.run_next(run_id))["next"] is None
    assert (await srv.run_control(run_id, "resume"))["run"]["state"] == "running"

    usage = await srv.run_usage(run_id, requests=5)
    assert usage["run"]["budget"]["requests"]["used"] == 5
    exceeded = await srv.run_usage(run_id, requests=1)
    assert exceeded["error"] == "invalid_input"

    status = await srv.run_status(run_id, include_events=True)
    assert status["tasks"]
    assert any(event["kind"] == "run_started" for event in status["events"])

    saved = await srv.run_artifact_add(run_id, "http", "proof.txt", "evidence")
    artifacts = await srv.run_artifacts(run_id)
    assert artifacts["artifacts"][0]["sha256"] == saved["artifact"]["sha256"]


@pytest.mark.asyncio
async def test_runs_resource_is_registered(fresh_context):
    resources = await srv.mcp.list_resources()
    assert "runs://recent" in {str(r.uri) for r in resources}
