"""Durable coordination under competing workers and ambiguous execution outcomes."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from moonmcp.runs import RunBudget, RunStore


def test_two_workers_claim_once_and_stale_worker_cannot_update(tmp_path, monkeypatch):
    path = str(tmp_path / "runs.db")
    first, second = RunStore(path), RunStore(path)
    try:
        run = first.create("example.test")
        task = first.add_task(run["id"], "Review one observation")
        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(executor.map(lambda pair: pair[0].claim_task(run["id"], pair[1]),
                                       [(first, "worker-a"), (second, "worker-b")]))
        claimed = [claim for claim in claims if claim is not None]
        assert len(claimed) == 1
        claim = claimed[0]
        with pytest.raises(ValueError, match="owner/token"):
            second.update_task(task["id"], "completed")
        with pytest.raises(ValueError, match="owner/token"):
            second.heartbeat(task["id"], "other", claim["claim_token"])
        first.heartbeat(task["id"], claim["owner"], claim["claim_token"])
        monkeypatch.setattr("moonmcp.runs.time.time", lambda: claim["lease_until"] + 100)
        assert second.recover_expired_tasks(run["id"]) == [task["id"]]
        assert second.task(task["id"])["state"] == "blocked"
        assert first.claim_task(run["id"], "replacement") is None
        with pytest.raises(ValueError, match="owner/token"):
            first.update_task(task["id"], "completed", owner=claim["owner"],
                              claim_token=claim["claim_token"])
        first.retry_task(task["id"], reason="Read-only observation checked against artifact")
        replacement = second.claim_task(run["id"], "replacement")
        assert replacement["attempts"] == 2
        assert replacement["claim_token"] != claim["claim_token"]
    finally:
        first.close()
        second.close()


def test_restart_preserves_receipt_and_idempotent_budget(tmp_path):
    path = str(tmp_path / "runs.db")
    first = RunStore(path)
    run = first.create("example.test", budget=RunBudget(2, 1, 1))
    receipt = first.begin_invocation(run["id"], "fixture", "sha256:args",
                                     idempotency_key="request-1", intrusive=True)
    first.consume_invocation_request(receipt["id"])
    first.finish_invocation(receipt["id"], "completed", {"ok": True, "data": "evidence"})
    first.close()
    resumed = RunStore(path)
    try:
        replay = resumed.begin_invocation(run["id"], "fixture", "sha256:args",
                                           idempotency_key="request-1", intrusive=True)
        assert replay["created"] is False
        assert replay["result"] == {"ok": True, "data": "evidence"}
        assert resumed.get(run["id"])["budget"]["tool_calls"]["used"] == 1
        assert resumed.get(run["id"])["budget"]["requests"]["used"] == 1
        with pytest.raises(ValueError, match="different invocation"):
            resumed.begin_invocation(run["id"], "fixture", "changed",
                                       idempotency_key="request-1", intrusive=True)
        with pytest.raises(ValueError, match="budget exceeded"):
            resumed.begin_invocation(run["id"], "fixture", "other", idempotency_key="new")
        assert len(resumed.brief(run["id"])["invocations"]) == 1
    finally:
        resumed.close()


def test_unknown_side_effect_after_lease_expiry_is_never_replayed(tmp_path, monkeypatch):
    store = RunStore(str(tmp_path / "runs.db"))
    try:
        run = store.create("example.test")
        store.add_task(run["id"], "Execute fixture")
        claim = store.claim_task(run["id"], "worker")
        record = store.begin_invocation(run["id"], "fixture", "args", task_id=claim["id"],
                                         owner="worker", claim_token=claim["claim_token"],
                                         idempotency_key="once")
        store.consume_invocation_request(record["id"])
        monkeypatch.setattr("moonmcp.runs.time.time", lambda: claim["lease_until"] + 1)
        packet = store.brief(run["id"])
        assert packet["invocations"][0]["state"] == "unknown"
        duplicate = store.begin_invocation(run["id"], "fixture", "args",
                                           task_id=claim["id"], idempotency_key="once")
        assert duplicate["created"] is False
        assert duplicate["state"] == "unknown"
        with pytest.raises(ValueError, match="invocation is unknown"):
            store.consume_invocation_request(record["id"])
        assert not store.finish(run["id"])["completed"]
    finally:
        store.close()


def test_invocation_budget_is_atomic_across_sessions_and_pause(tmp_path):
    path = str(tmp_path / "runs.db")
    one, two = RunStore(path), RunStore(path)
    try:
        run = one.create("example.test", budget=RunBudget(1, 2, 0))
        with ThreadPoolExecutor(max_workers=2) as executor:
            receipts = list(executor.map(lambda store: store.begin_invocation(
                run["id"], "fixture", "args", idempotency_key="one"), [one, two]))
        assert sum(receipt["created"] for receipt in receipts) == 1
        assert one.get(run["id"])["budget"]["tool_calls"]["used"] == 1
        receipt = receipts[0]
        one.set_state(run["id"], "paused")
        with pytest.raises(ValueError, match="run is paused"):
            two.consume_invocation_request(receipt["id"])
        one.set_state(run["id"], "running")
        two.consume_invocation_request(receipt["id"])
        with pytest.raises(ValueError, match="budget exceeded"):
            one.consume_invocation_request(receipt["id"])
        assert two.get_invocation(receipt["id"])["requests_used"] == 1
        two.finish_invocation(receipt["id"], "failed", {"error": "transport"})
        with pytest.raises(ValueError, match="already finalized"):
            one.finish_invocation(receipt["id"], "completed", {"ok": True})
    finally:
        one.close()
        two.close()


def test_forced_completion_keeps_limitations_after_reopen(tmp_path):
    path = str(tmp_path / "runs.db")
    store = RunStore(path)
    run = store.create("example.test")
    task = store.add_task(run["id"], "Unavailable check")
    store.update_task(task["id"], "failed", result="missing dependency")
    store.set_coverage(run["id"], "browser", "blocked", evidence="browser unavailable")
    result = store.finish(run["id"])
    assert result["completed"] is False
    assert len(result["limitations"]) == 2
    forced = store.finish(run["id"], force=True)
    assert forced["forced"] is True
    store.close()
    resumed = RunStore(path)
    try:
        packet = resumed.brief(run["id"])
        assert packet["limitations"] == result["limitations"]
        assert packet["run"]["state"] == "completed"
        with pytest.raises(ValueError, match="transition"):
            resumed.set_state(run["id"], "running")
        with pytest.raises(ValueError, match="terminal run"):
            resumed.update_task(task["id"], "completed")
    finally:
        resumed.close()


def test_old_database_gets_lease_columns_without_losing_tasks(tmp_path):
    import sqlite3

    path = str(tmp_path / "legacy.db")
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE tasks(id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT,
        title TEXT,role TEXT,state TEXT,priority INTEGER,depends_on INTEGER,detail TEXT,
        result TEXT,created_at TEXT,updated_at TEXT)""")
    db.commit()
    db.close()
    store = RunStore(path)
    try:
        run = store.create("example.test")
        task = store.add_task(run["id"], "Migrated task")
        assert task["owner"] == ""
        assert task["lease_until"] is None
        assert store.claim_task(run["id"], "worker")["id"] == task["id"]
    finally:
        store.close()


def test_invocation_event_failure_rolls_back_receipt_and_budget(tmp_path, monkeypatch):
    path = str(tmp_path / "runs.db")
    first, second = RunStore(path), RunStore(path)
    try:
        run = first.create("example.test", budget=RunBudget(0, 1, 0))
        original_event = first._event

        def fail_after_reservation(run_id, kind, payload):
            if kind == "invocation_started":
                raise RuntimeError("receipt journal unavailable")
            original_event(run_id, kind, payload)

        monkeypatch.setattr(first, "_event", fail_after_reservation)
        with pytest.raises(RuntimeError, match="journal unavailable"):
            first.begin_invocation(run["id"], "fixture", "args", idempotency_key="key")
        assert second.get(run["id"])["budget"]["tool_calls"]["used"] == 0
        assert second.begin_invocation(run["id"], "fixture", "args",
                                        idempotency_key="key")["created"] is True
    finally:
        first.close()
        second.close()


def test_unleased_running_receipt_survives_restart_without_reexecution(tmp_path):
    path = str(tmp_path / "runs.db")
    store = RunStore(path)
    run = store.create("example.test")
    initial = store.begin_invocation(run["id"], "fixture", "args", idempotency_key="once")
    store.close()
    resumed = RunStore(path)
    try:
        existing = resumed.begin_invocation(run["id"], "fixture", "args", idempotency_key="once")
        assert existing["id"] == initial["id"]
        assert existing["created"] is False
        assert existing["state"] == "running"
        assert resumed.finish(run["id"])["completed"] is False
        resumed.finish_invocation(initial["id"], "unknown", {"error": "worker lost"})
        assert resumed.get_invocation(initial["id"])["state"] == "unknown"
    finally:
        resumed.close()


def test_artifact_read_scoped_lookup_beyond_listing_limit_and_unicode_chunks():
    store = RunStore()
    try:
        run = store.create("example.test")
        other_run = store.create("other.test")
        for number in range(501):
            store.add_artifact(run["id"], "fixture", f"filler-{number}", "filler")
        content = "А🙂文\x00more evidence"
        artifact = store.add_artifact(run["id"], "fixture", "proof", content)
        assert artifact["id"] not in {row["id"] for row in store.artifacts(run["id"], limit=500)}
        first = store.artifact_read(run["id"], artifact["id"], limit=4)
        assert first["content"] == content[:4]
        assert first["total_chars"] == len(content)
        assert first["next_offset"] == 4
        last = store.artifact_read(run["id"], artifact["id"], offset=first["next_offset"])
        assert first["content"] + last["content"] == content
        assert last["next_offset"] is None
        assert store.get_artifact(run["id"], artifact["id"])["content"] == content
        with pytest.raises(ValueError, match="unknown artifact"):
            store.get_artifact(other_run["id"], artifact["id"])
        assert last["sha256"] == artifact["sha256"]
        assert last["uri"] == artifact["uri"]
        assert last["uri"] == f"moonmcp://runs/{run['id']}/artifacts/{artifact['id']}"
        assert store.artifact_read(run["id"], artifact["id"], offset=999)["content"] == ""
        with pytest.raises(ValueError, match="unknown artifact"):
            store.artifact_read(other_run["id"], artifact["id"])
    finally:
        store.close()


@pytest.mark.parametrize("arguments", [
    {"offset": -1}, {"limit": -1}, {"limit": 0}, {"limit": 65537},
    {"offset": True}, {"limit": 1.5},
])
def test_artifact_read_rejects_invalid_chunk_arguments(arguments):
    store = RunStore()
    try:
        run = store.create("example.test")
        artifact = store.add_artifact(run["id"], "fixture", "proof", "content")
        with pytest.raises(ValueError):
            store.artifact_read(run["id"], artifact["id"], **arguments)
    finally:
        store.close()


def test_reconcile_unknown_receipt_is_durable_and_does_not_enable_replay(tmp_path):
    path = str(tmp_path / "runs.db")
    store = RunStore(path)
    run = store.create("example.test")
    receipt = store.begin_invocation(run["id"], "fixture", "args", idempotency_key="once")
    original_result = {"error": "transport outcome unknown"}
    store.finish_invocation(receipt["id"], "unknown", original_result)
    assert store.finish(run["id"])["completed"] is False
    proof = store.add_artifact(run["id"], "review", "read-back", "verified expected state")
    resolved = store.reconcile_invocation(receipt["id"], "completed", "Read-back confirmed effect",
                                          [proof["id"]])
    assert resolved["state"] == "unknown"
    assert resolved["result"] == original_result
    assert resolved["resolution"]["outcome"] == "completed"
    assert store.reconcile_invocation(receipt["id"], "completed", "Read-back confirmed effect",
                                      [proof["id"]]) == resolved
    assert sum(event["kind"] == "invocation_reconciled" for event in store.events(run["id"])) == 1
    store.close()
    resumed = RunStore(path)
    try:
        replay = resumed.begin_invocation(run["id"], "fixture", "args", idempotency_key="once")
        assert replay["created"] is False
        assert replay["state"] == "unknown"
        assert replay["resolution"] == resolved["resolution"]
        assert resumed.brief(run["id"])["invocations"][0]["resolution"] == resolved["resolution"]
        with pytest.raises(ValueError, match="invocation is unknown"):
            resumed.consume_invocation_request(receipt["id"])
        with pytest.raises(ValueError, match="immutable"):
            resumed.reconcile_invocation(receipt["id"], "failed", "Changed decision", [proof["id"]])
        assert resumed.finish(run["id"])["completed"] is True
    finally:
        resumed.close()


def test_reconciliation_requires_same_run_evidence_and_unknown_outcome():
    store = RunStore()
    try:
        run, other = store.create("one.test"), store.create("two.test")
        receipt = store.begin_invocation(run["id"], "fixture", "args")
        proof = store.add_artifact(run["id"], "review", "proof", "evidence")
        with pytest.raises(ValueError, match="only unknown"):
            store.reconcile_invocation(receipt["id"], "completed", "Review", [proof["id"]])
        store.finish_invocation(receipt["id"], "unknown", {"error": "lost response"})
        for evidence in ([], [True], [-1], ["1"]):
            with pytest.raises(ValueError, match="evidence artifact"):
                store.reconcile_invocation(receipt["id"], "not_executed", "Review", evidence)
        with pytest.raises(ValueError, match="reason"):
            store.reconcile_invocation(receipt["id"], "completed", " ", [proof["id"]])
        foreign = store.add_artifact(other["id"], "review", "foreign", "wrong assessment")
        with pytest.raises(ValueError, match="unknown artifact"):
            store.reconcile_invocation(receipt["id"], "completed", "Review", [foreign["id"]])
        assert store.get_invocation(receipt["id"])["resolution"] is None
        assert store.finish(run["id"])["completed"] is False
    finally:
        store.close()


def test_reconciliation_event_failure_rolls_back_append(tmp_path, monkeypatch):
    path = str(tmp_path / "runs.db")
    first, second = RunStore(path), RunStore(path)
    try:
        run = first.create("example.test")
        receipt = first.begin_invocation(run["id"], "fixture", "args")
        first.finish_invocation(receipt["id"], "unknown", {"error": "unknown"})
        proof = first.add_artifact(run["id"], "review", "proof", "evidence")

        def fail_event(*args):
            raise RuntimeError("journal unavailable")

        monkeypatch.setattr(first, "_event", fail_event)
        with pytest.raises(RuntimeError, match="journal unavailable"):
            first.reconcile_invocation(receipt["id"], "not_executed", "Verified no send",
                                       [proof["id"]])
        assert second.get_invocation(receipt["id"])["resolution"] is None
        assert second.reconcile_invocation(receipt["id"], "not_executed", "Verified no send",
                                            [proof["id"]])["resolution"] is not None
    finally:
        first.close()
        second.close()


def test_retry_requires_resolution_of_ambiguous_task_execution(monkeypatch):
    store = RunStore()
    try:
        run = store.create("example.test")
        task = store.add_task(run["id"], "Read controlled fixture")
        claim = store.claim_task(run["id"], "worker")
        invocation = store.begin_invocation(run["id"], "fixture", "args", task_id=task["id"],
                                             owner="worker", claim_token=claim["claim_token"])
        monkeypatch.setattr("moonmcp.runs.time.time", lambda: claim["lease_until"] + 1)
        store.recover_expired_tasks(run["id"])
        with pytest.raises(ValueError, match="unresolved invocation"):
            store.retry_task(task["id"], reason="Worker stopped")
        proof = store.add_artifact(run["id"], "review", "request-log", "No dispatch occurred")
        store.reconcile_invocation(invocation["id"], "not_executed", "Checked request log",
                                    [proof["id"]])
        assert store.retry_task(task["id"], reason="Confirmed safe to retry")["state"] == "pending"
        assert store.get_invocation(invocation["id"])["state"] == "unknown"
    finally:
        store.close()


def test_taskless_hard_crash_requires_explicit_paused_recovery(tmp_path):
    path = str(tmp_path / "runs.db")
    original = RunStore(path)
    run = original.create("example.test")
    receipt = original.begin_invocation(run["id"], "fixture", "args", idempotency_key="once")
    original.close()
    recovered, late_worker = RunStore(path), RunStore(path)
    try:
        with pytest.raises(ValueError, match="pause, cancel or fail"):
            recovered.mark_invocation_unknown(receipt["id"], "Previous worker has stopped")
        assert recovered.get_invocation(receipt["id"])["state"] == "running"
        recovered.set_state(run["id"], "paused")
        unknown = recovered.mark_invocation_unknown(receipt["id"], "Previous worker has stopped")
        assert unknown["state"] == "unknown"
        assert unknown["result"] is None
        assert recovered.mark_invocation_unknown(receipt["id"], "Previous worker has stopped") == unknown
        assert sum(event["kind"] == "invocation_recovered_unknown"
                   for event in recovered.events(run["id"])) == 1
        with pytest.raises(ValueError, match="already finalized"):
            late_worker.finish_invocation(receipt["id"], "completed", {"ok": True})
        proof = recovered.add_artifact(run["id"], "review", "service-log", "Operation not executed")
        recovered.reconcile_invocation(receipt["id"], "not_executed", "Checked service log",
                                        [proof["id"]])
        assert recovered.finish(run["id"])["completed"] is True
        replay = recovered.begin_invocation(run["id"], "fixture", "args", idempotency_key="once")
        assert replay["created"] is False
        assert replay["state"] == "unknown"
        assert replay["resolution"]["outcome"] == "not_executed"
    finally:
        recovered.close()
        late_worker.close()


def test_recovery_rejects_live_claim_and_known_terminal_outcome(monkeypatch):
    store = RunStore()
    try:
        run = store.create("example.test")
        store.add_task(run["id"], "Controlled fixture")
        claim = store.claim_task(run["id"], "worker")
        receipt = store.begin_invocation(run["id"], "fixture", "args", task_id=claim["id"],
                                          owner="worker", claim_token=claim["claim_token"])
        completed = store.begin_invocation(run["id"], "other", "args")
        store.finish_invocation(completed["id"], "completed", {"ok": True})
        store.set_state(run["id"], "paused")
        with pytest.raises(ValueError, match="lease is still active"):
            store.mark_invocation_unknown(receipt["id"], "Worker presumed stopped")
        with pytest.raises(ValueError, match="interrupted running"):
            store.mark_invocation_unknown(completed["id"], "Cannot override known result")
        with pytest.raises(ValueError, match="reason"):
            store.mark_invocation_unknown(receipt["id"], " ")
        monkeypatch.setattr("moonmcp.runs.time.time", lambda: claim["lease_until"] + 1)
        assert store.mark_invocation_unknown(receipt["id"], "Worker stopped, lease expired")["state"] == "unknown"
    finally:
        store.close()
