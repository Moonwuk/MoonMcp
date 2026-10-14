"""Findings survive restarts without recycling IDs or losing operator verdicts."""

from concurrent.futures import ThreadPoolExecutor

from moonmcp.findings import FindingsStore


def test_reopen_preserves_findings_outcomes_and_monotonic_ids(tmp_path):
    path = str(tmp_path / "findings.db")
    first = FindingsStore(db_path=path)
    finding = first.add(target="example.test", severity="high", title="Access boundary",
                        evidence="artifact:1", source="controlled test")
    first.set_outcome(finding.id, "true_positive")
    first.close()

    resumed = FindingsStore(db_path=path)
    loaded = resumed.list()[0]
    assert loaded.id == finding.id
    assert loaded.evidence == "artifact:1"
    assert loaded.outcome == "true_positive"
    assert resumed.clear() == 1
    resumed.close()
    again = FindingsStore(db_path=path)
    assert again.add(target="example.test", severity="info", title="New").id > finding.id
    again.close()


def test_two_sessions_do_not_overwrite_findings_or_labels(tmp_path):
    path = str(tmp_path / "findings.db")
    one, two = FindingsStore(db_path=path), FindingsStore(db_path=path)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda pair: pair[0].add(
                target="example.test", severity="low", title=pair[1]),
                [(one, "First"), (two, "Second")]))
        assert len({finding.id for finding in results}) == 2
        two.set_outcome(results[0].id, "false_positive")
        assert next(f for f in one.list() if f.id == results[0].id).outcome == "false_positive"
        assert {finding.title for finding in two.list()} == {"First", "Second"}
    finally:
        one.close()
        two.close()


def test_dedupe_and_retention_are_durable(tmp_path):
    path = str(tmp_path / "findings.db")
    store = FindingsStore(cap=2, db_path=path)
    one = store.add(target="example.test", severity="high", title="Same", evidence="one")
    store.add(target="example.test", severity="high", title="Same", evidence="two")
    assert store.dedupe() == {"removed": 1, "remaining": 1}
    store.close()
    resumed = FindingsStore(cap=2, db_path=path)
    assert resumed.list()[0].id == one.id
    assert resumed.list()[0].evidence == "one | two"
    resumed.add(target="example.test", severity="info", title="Next")
    final = resumed.add(target="example.test", severity="info", title="Last")
    assert {finding.title for finding in resumed.list()} == {"Next", "Last"}
    assert final.id == 4
    resumed.close()


def test_run_findings_survive_restart_without_cross_run_dedup(tmp_path):
    path = str(tmp_path / "findings.db")
    store = FindingsStore(db_path=path)
    for run_id in ("run-a", "run-b", ""):
        store.add(target="shared.test", severity="high", title="Same observation",
                  run_id=run_id, evidence=f"evidence:{run_id}")
    assert store.dedupe() == {"removed": 0, "remaining": 3}
    store.close()
    resumed = FindingsStore(db_path=path)
    try:
        assert resumed.summary(run_id="run-a")["total"] == 1
        assert resumed.list(run_id="run-b")[0].evidence == "evidence:run-b"
        assert resumed.as_dict(run_id="")["findings"][0]["run_id"] == ""
        assert resumed.list(run_id="missing") == []
    finally:
        resumed.close()


def test_existing_findings_database_migrates_run_association(tmp_path):
    import sqlite3

    path = str(tmp_path / "legacy.db")
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,target TEXT NOT NULL,severity TEXT NOT NULL,
        title TEXT NOT NULL,type TEXT NOT NULL,detail TEXT NOT NULL,evidence TEXT NOT NULL,
        source TEXT NOT NULL,created_at TEXT NOT NULL,outcome TEXT NOT NULL DEFAULT '')""")
    db.execute("""INSERT INTO findings VALUES
        (17,'example.test','high','Legacy finding','manual','','proof','fixture','','true_positive')""")
    db.commit()
    db.close()
    store = FindingsStore(db_path=path)
    try:
        legacy = store.list(run_id="")[0]
        assert legacy.id == 17
        assert legacy.outcome == "true_positive"
        assert store.add(target="example.test", severity="low", title="Associated",
                         run_id="run-a").id > 17
        assert store.list(run_id="run-a")[0].title == "Associated"
    finally:
        store.close()


def test_callbacks_infer_run_at_write_time_and_explicit_run_takes_precedence(tmp_path):
    current = {"run_id": "active-a"}
    recorded = []
    store = FindingsStore.from_env(str(tmp_path),
                                   run_id_provider=lambda: current["run_id"],
                                   on_record=recorded.append)
    try:
        inferred = store.add(target="example.test", severity="low", title="Automatic")
        assert inferred.run_id == "active-a"
        current["run_id"] = "active-b"
        assert store.add(target="example.test", severity="info", title="Later").run_id == "active-b"
        assert store.add(target="example.test", severity="info", title="Explicit",
                         run_id="manual").run_id == "manual"
        assert store.add(target="example.test", severity="info", title="Unassociated",
                         run_id="").run_id == ""
        assert [finding.run_id for finding in recorded] == ["active-a", "active-b", "manual", ""]
        store.run_id_provider = lambda: None
        assert store.add(target="example.test", severity="info", title="No active run").run_id == ""
        assert store.list(run_id="active-a")[0].id == inferred.id
    finally:
        store.close()


def test_observer_failure_does_not_erase_or_fail_a_durable_finding(tmp_path, caplog):
    def failing_observer(finding):
        raise RuntimeError("sensitive exception payload must not be logged")

    path = str(tmp_path / "findings.db")
    store = FindingsStore(db_path=path, on_record=failing_observer)
    finding = store.add(target="example.test", severity="info", title="Persisted first")
    store.close()
    resumed = FindingsStore(db_path=path)
    try:
        assert resumed.list()[0].id == finding.id
        assert "Finding observer failed: RuntimeError" in caplog.text
        assert "sensitive exception payload" not in caplog.text
    finally:
        resumed.close()
