"""Tests for attack-surface change tracking (baseline + diff)."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.monitor import SnapshotStore


def test_snapshot_diff_in_memory():
    s = SnapshotStore()
    first = s.diff("subs", ["a.example.com", "b.example.com"])
    assert first["baseline_created"] is True and first["total"] == 2
    second = s.diff("subs", ["b.example.com", "c.example.com"])
    assert second["baseline_created"] is False
    assert second["added"] == ["c.example.com"]
    assert second["removed"] == ["a.example.com"]
    # a third run with no change → empty deltas
    third = s.diff("subs", ["b.example.com", "c.example.com"])
    assert third["added_count"] == 0 and third["removed_count"] == 0
    assert "subs" in s.names()


def test_snapshot_persistence(tmp_path):
    d = str(tmp_path)
    s1 = SnapshotStore(state_dir=d)
    s1.diff("hosts", ["x", "y"])
    # a fresh store (new process) reads the persisted baseline from disk
    s2 = SnapshotStore(state_dir=d)
    res = s2.diff("hosts", ["y", "z"])
    assert res["baseline_created"] is False
    assert res["added"] == ["z"] and res["removed"] == ["x"]
    # the snapshot file exists and is valid JSON
    files = list(tmp_path.glob("snap-*.json"))
    assert files and isinstance(json.load(open(files[0])), list)


def test_snapshot_clear():
    s = SnapshotStore()
    s.diff("a", ["1"])
    s.diff("b", ["2"])
    assert s.clear("a") == 1
    assert "a" not in s.names() and "b" in s.names()
    assert s.clear() == 1  # clears remaining


@pytest.mark.asyncio
async def test_surface_tools(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "surface_diff" in tools and "surface_snapshots" not in tools
    await srv.surface_diff(name="ep", items=["/a", "/b"])
    d = await srv.surface_diff(name="ep", items=["/b", "/c"])
    assert d["added"] == ["/c"] and d["removed"] == ["/a"]
    # list mode: omit items
    snaps = await srv.surface_diff()
    assert snaps["snapshots"].get("ep") == 2
    # clear mode
    cleared = await srv.surface_diff(clear="ep")
    assert cleared["cleared"] == 1
