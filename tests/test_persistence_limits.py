"""Persistence limits and failure paths without external traffic."""

import hashlib
import io
import json
import logging
import multiprocessing
import os
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from moonmcp import audit, persistence
from moonmcp.audit import AuditLog
from moonmcp.monitor import SnapshotStore


def test_logging_refreshes_only_its_managed_stderr(monkeypatch):
    logger = audit.setup_logging()
    foreign_stream = io.StringIO()
    foreign = logging.StreamHandler(foreign_stream)
    logger.addHandler(foreign)
    try:
        with monkeypatch.context() as patch:
            replacement = io.StringIO()
            patch.setattr(sys, "stderr", replacement)
            audit.setup_logging()
            audit.setup_logging()
            own = [handler for handler in logger.handlers
                   if getattr(handler, "_moonmcp_stderr", False)]
            assert len(own) == 1 and own[0].stream is replacement
            assert foreign.stream is foreign_stream
        audit.setup_logging()
    finally:
        logger.removeHandler(foreign)
        foreign.close()


@pytest.mark.parametrize("max_bytes", [512, 100_000])
def test_audit_oversize_digest_and_reserved_fields_are_trusted(tmp_path, monkeypatch, max_bytes):
    monkeypatch.setattr(audit, "_now", lambda: "2026-10-21T00:00:00Z")
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=str(path), max_bytes=max_bytes, backup_count=1)
    event = "trusted-operation-long"
    fields = {"ts": "forged-time", "event": "forged-event", "text": "€" * 25_000}
    original = {**fields, "ts": "2026-10-21T00:00:00Z", "event": event}
    raw = (json.dumps(original, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False) + "\n").encode("utf-8")
    result = log.record(event, **fields)
    assert result["ts"] == "2026-10-21T00:00:00Z"
    assert result["event"] == event[:16]
    assert result["oversized"]
    assert result["original_bytes"] == len(raw)
    assert result["sha256"] == hashlib.sha256(raw).hexdigest()
    assert len(path.read_bytes()) <= min(max_bytes, 65_536)
    assert json.loads(path.read_text()) == result == log.recent()[-1]
    assert log.record(event="keyword-compatible")["event"] == "keyword-compatible"


def test_audit_legacy_constructor_cap_and_keyword_event_are_compatible(tmp_path):
    log = AuditLog(str(tmp_path / "legacy.jsonl"), 2)
    for index in range(4):
        log.record(event="legacy", index=index)
    assert [item["index"] for item in log.recent()] == [2, 3]
    assert log.summary()["by_event"] == {"legacy": 2}
    assert len((tmp_path / "legacy.jsonl").read_text().splitlines()) == 4


def test_audit_unicode_rotation_preserves_complete_jsonl_and_lock_inode(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=str(path), max_bytes=512, backup_count=2)
    log.record("unicode", index=0, text="я" * 110)
    inode = (tmp_path / "audit.jsonl.lock").stat().st_ino
    for index in range(1, 10):
        log.record("unicode", index=index, text="я" * 110)
    files = [path, tmp_path / "audit.jsonl.1", tmp_path / "audit.jsonl.2"]
    assert not (tmp_path / "audit.jsonl.3").exists()
    for file in files:
        raw = file.read_bytes()
        assert raw.endswith(b"\n") and len(raw) <= 512
        assert all(json.loads(line)["event"] == "unicode" for line in raw.splitlines())
    assert (tmp_path / "audit.jsonl.lock").stat().st_ino == inode
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "audit.jsonl.lock").stat().st_mode) == 0o600


def test_rotation_preserves_a_whole_legacy_oversized_segment(tmp_path):
    path = tmp_path / "audit.jsonl"
    original = b'{"legacy":true}\n' * 100
    path.write_bytes(original)
    log = AuditLog(path=str(path), max_bytes=512, backup_count=1)
    log.record("current")
    assert (tmp_path / "audit.jsonl.1").read_bytes() == original
    assert json.loads(path.read_text())["event"] == "current"


def test_audit_fsync_and_failure_remain_observable(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(audit.os, "fsync", lambda fd: calls.append(fd))
    log = AuditLog(path=str(tmp_path / "audit.jsonl"), max_bytes=512)
    log.record("persist")
    assert len(calls) >= (1 if os.name == "nt" else 2)
    assert log.summary()["retention"]["fsync"] is True
    broken = AuditLog(path=str(tmp_path), max_bytes=512)
    assert broken.record("retained-in-memory")["event"] == "retained-in-memory"
    assert broken.recent() and broken.summary()["write_error"]
    assert broken.recent(0) == [] and broken.recent(-1) == []


def test_audit_instances_share_rotation_lock(tmp_path):
    path = tmp_path / "audit.jsonl"
    logs = [AuditLog(path=str(path), max_bytes=4096, backup_count=2) for _ in range(4)]

    def record(index):
        logs[index % len(logs)].record("thread", index=index, text="λ" * 25)

    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(record, range(60)))
    entries = []
    for file in [path, tmp_path / "audit.jsonl.1", tmp_path / "audit.jsonl.2"]:
        if file.exists():
            raw = file.read_bytes()
            assert len(raw) <= 4096 and raw.endswith(b"\n")
            entries.extend(json.loads(line) for line in raw.splitlines())
    ids = [entry["index"] for entry in entries]
    assert ids and len(ids) == len(set(ids))
    assert sum(len(log.recent()) for log in logs) == 60


def test_path_lock_serializes_threads_and_is_reentrant(tmp_path):
    path = tmp_path / "shared"
    state = {"count": 0}

    def increment(_):
        with persistence.path_lock(path), persistence.path_lock(path):
            previous = state["count"]
            time.sleep(0.001)
            state["count"] = previous + 1

    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(increment, range(24)))
    assert state["count"] == 24
    assert (tmp_path / "shared.lock").exists()


def test_snapshot_external_updates_and_aliases_are_reloaded(tmp_path):
    one = SnapshotStore(str(tmp_path))
    two = SnapshotStore(str(tmp_path))
    assert one.diff("Alias Name", ["before"])["baseline_created"]
    assert two.diff("alias-name", ["before", "external"])["added"] == ["external"]
    changed = one.diff("ALIAS NAME", ["external"])
    assert changed["removed"] == ["before"] and changed["added"] == []
    assert one.names() == {"alias-name": 1}
    assert len(list(tmp_path.glob("snap-*.json"))) == 1


def test_snapshot_limits_count_distinct_items_and_utf8_bytes(tmp_path):
    store = SnapshotStore(str(tmp_path), max_snapshots=1, max_items=2, max_bytes=20)
    assert store.diff("first", ["a", "a", "b"])["total"] == 2
    original = (tmp_path / "snap-first.json").read_bytes()
    with pytest.raises(ValueError, match="max_items"):
        store.diff("first", ["a", "b", "c"])
    with pytest.raises(ValueError, match="max_bytes"):
        store.diff("first", ["я" * 10])
    with pytest.raises(ValueError, match="max_snapshots"):
        SnapshotStore(str(tmp_path), max_snapshots=1).diff("second", ["c"])
    assert (tmp_path / "snap-first.json").read_bytes() == original


@pytest.mark.parametrize("raw", [
    b"{not-json", b'{"not":"a-list"}', b'["old",7]', b'["a","b","c"]',
    b'["' + b"x" * 70 + b'"]',
])
def test_corrupt_snapshot_does_not_silently_create_a_new_baseline(tmp_path, raw):
    store = SnapshotStore(str(tmp_path), max_items=2, max_bytes=64)
    store.diff("surface", ["old"])
    path = tmp_path / "snap-surface.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="unreadable or corrupt"):
        store.diff("surface", ["new"])
    assert path.read_bytes() == raw
    assert store._mem["surface"] == {"old"}


def test_failed_atomic_replace_preserves_baseline_and_removes_temporary_file(tmp_path, monkeypatch):
    store = SnapshotStore(str(tmp_path))
    store.diff("surface", ["old"])
    path = tmp_path / "snap-surface.json"
    original = path.read_bytes()

    def fail(*args, **kwargs):
        raise OSError("replacement denied")

    with monkeypatch.context() as patch:
        patch.setattr(persistence.os, "replace", fail)
        with pytest.raises(ValueError, match="unconfirmed"):
            store.diff("surface", ["new"])
    assert path.read_bytes() == original and store._mem["surface"] == {"old"}
    assert not list(tmp_path.glob(".snap-*.tmp"))
    assert store.diff("surface", ["old"])["added"] == []
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_snapshot_clear_removes_persisted_files_without_a_warm_cache(tmp_path):
    first = SnapshotStore(str(tmp_path))
    first.diff("one", ["a"])
    first.diff("two", ["b"])
    cold = SnapshotStore(str(tmp_path))
    assert cold.names() == {"one": 1, "two": 1}
    assert cold.clear() == 2
    assert not list(tmp_path.glob("snap-*.json"))
    assert SnapshotStore(str(tmp_path)).names() == {}


@pytest.mark.parametrize("options", [
    {"max_snapshots": 0}, {"max_items": True}, {"max_bytes": -1},
])
def test_snapshot_constructor_rejects_invalid_limits(options):
    with pytest.raises(ValueError, match="positive integer"):
        SnapshotStore(**options)


@pytest.mark.parametrize("options", [
    {"max_bytes": 511}, {"max_bytes": True}, {"backup_count": -1},
    {"backup_count": 21}, {"backup_count": True},
])
def test_audit_constructor_rejects_invalid_retention(options):
    with pytest.raises(ValueError):
        AuditLog(**options)


def test_audit_environment_controls_retention(tmp_path, monkeypatch):
    monkeypatch.setenv("MOONMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("MOONMCP_AUDIT_MAX_BYTES", "1024")
    monkeypatch.setenv("MOONMCP_AUDIT_BACKUPS", "2")
    monkeypatch.setenv("MOONMCP_AUDIT_FSYNC", "0")
    log = AuditLog.from_env()
    assert log.max_bytes == 1024 and log.backup_count == 2 and not log.fsync


@pytest.mark.parametrize("persisted", [False, True])
def test_snapshot_names_are_bounded_before_consuming_items_or_touching_disk(tmp_path, persisted):
    state_dir = tmp_path / "state"
    store = SnapshotStore(str(state_dir) if persisted else None)
    too_long = "a" * 121
    items = iter(["unconsumed"])
    with pytest.raises(ValueError, match="120"):
        store.diff(too_long, items)
    assert next(items) == "unconsumed"
    with pytest.raises(ValueError, match="120"):
        store.clear(too_long)
    assert store._mem == {}
    assert not state_dir.exists()
    longest = "a" * 120
    assert store.diff(" " + longest.upper() + " ", ["old"])["baseline_created"]
    assert store.names() == {longest: 1}
    assert store.clear(longest.upper()) == 1


def test_rejected_overcapacity_disk_reads_cannot_grow_the_snapshot_cache(tmp_path):
    store = SnapshotStore(str(tmp_path), max_snapshots=1)
    for key in ("one", "two", "three"):
        (tmp_path / f"snap-{key}.json").write_text('["old"]')
    for key in ("one", "two", "three"):
        with pytest.raises(ValueError, match="max_snapshots"):
            store.diff(key, ["new"])
        assert store._mem == {}
        assert (tmp_path / f"snap-{key}.json").read_text() == '["old"]'


def test_snapshot_names_stage_reads_and_prune_stale_cache_before_corruption(tmp_path):
    store = SnapshotStore(str(tmp_path), max_snapshots=2)
    store.diff("stale", ["old"])
    for index in range(4):
        for path in tmp_path.glob("snap-*.json"):
            path.unlink()
        valid, broken = f"a-{index}", f"z-{index}"
        (tmp_path / f"snap-{valid}.json").write_text('["valid"]')
        corrupt = tmp_path / f"snap-{broken}.json"
        corrupt.write_text("{broken")
        with pytest.raises(ValueError, match="unreadable or corrupt"):
            store.names()
        assert store._mem == {}
        assert corrupt.read_text() == "{broken"
        corrupt.write_text('["repaired"]')
        assert store.names() == {valid: 1, broken: 1}
        assert len(store._mem) == 2


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "mkfifo"), reason="POSIX FIFO required")
def test_snapshot_fifo_is_rejected_without_blocking_or_rebaselining(tmp_path):
    path = tmp_path / "snap-surface.json"
    os.mkfifo(path)
    script = """
import sys
from moonmcp.monitor import SnapshotStore
store = SnapshotStore(sys.argv[1])
try:
    store.diff("surface", ["new"])
except ValueError as exc:
    assert "unreadable or corrupt" in str(exc)
else:
    raise AssertionError("FIFO accepted as a snapshot baseline")
assert store._mem == {}
"""
    subprocess.run([sys.executable, "-c", script, str(tmp_path)],
                   check=True, capture_output=True, text=True, timeout=5)
    assert stat.S_ISFIFO(path.stat().st_mode)


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "mkfifo"), reason="POSIX FIFO required")
@pytest.mark.parametrize("with_reader", [False, True])
def test_audit_fifo_fails_without_blocking_or_writing_bytes(tmp_path, with_reader):
    path = tmp_path / "audit.jsonl"
    os.mkfifo(path)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK) if with_reader else None
    script = """
import sys
from moonmcp.audit import AuditLog
log = AuditLog(path=sys.argv[1])
entry = log.record("fifo")
assert entry["event"] == "fifo"
assert log.recent() == [entry]
assert log.summary()["write_error"]
"""
    try:
        subprocess.run([sys.executable, "-c", script, str(path)],
                       check=True, capture_output=True, text=True, timeout=5)
        if reader is not None:
            assert os.read(reader, 1024) == b""
        assert stat.S_ISFIFO(path.stat().st_mode)
    finally:
        if reader is not None:
            os.close(reader)


def _record_audit_process(path, worker, barrier):
    log = AuditLog(path=path, max_bytes=1024, backup_count=20, fsync=True)
    barrier.wait(timeout=20)
    for sequence in range(20):
        log.record("process", worker=worker, sequence=sequence)
    if log.summary()["write_error"] is not None:
        raise RuntimeError(log.summary()["write_error"])


def test_spawned_processes_share_audit_rotation_without_lost_or_duplicate_records(tmp_path):
    path = tmp_path / "audit.jsonl"
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    processes = [
        context.Process(target=_record_audit_process, args=(str(path), worker, barrier))
        for worker in range(4)
    ]
    started = []
    try:
        for process in processes:
            process.start()
            started.append(process)
        deadline = time.monotonic() + 40
        for process in started:
            process.join(timeout=max(0, deadline - time.monotonic()))
        assert all(not process.is_alive() for process in started)
        assert [process.exitcode for process in started] == [0, 0, 0, 0]
    finally:
        for process in started:
            if process.is_alive():
                process.terminate()
        for process in started:
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)

    segments = [path] + [
        tmp_path / f"audit.jsonl.{number}" for number in range(1, 21)
        if (tmp_path / f"audit.jsonl.{number}").exists()
    ]
    assert len(segments) > 1
    entries = []
    for segment in segments:
        raw = segment.read_bytes()
        assert raw.endswith(b"\n") and len(raw) <= 1024
        entries.extend(json.loads(line) for line in raw.splitlines())
    expected = {(worker, sequence) for worker in range(4) for sequence in range(20)}
    actual = [(entry["worker"], entry["sequence"]) for entry in entries]
    assert len(actual) == len(expected) and set(actual) == expected
    assert all(entry["event"] == "process" for entry in entries)
