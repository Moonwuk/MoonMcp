"""Stage 0 baseline scenarios must stay reproducible and cheap.

AGENT_NAVIGATION_PLAN.md stage 0: the scenarios are the measurement
contract — every scenario runs offline, makes real tool calls, and the
numbers (calls, duration, slice vs full schema) must stay bounded.
"""

import pytest

from moonmcp import bench


def test_all_scenarios_run_and_report():
    report = bench.run_baselines()
    assert report["stage"] == "0-baseline"
    assert report["total_scenarios"] == len(bench.ALL_SCENARIOS) == 7

    full = report["full_schema_bytes"]
    assert full > 100_000, "full tools schema unexpectedly small"

    for s in report["scenarios"]:
        assert s["outcomes"] and all(s["outcomes"].values())
        # every scenario makes at least one REAL call
        assert s["tool_calls"] >= 1, f"{s['name']}: no calls recorded"
        assert len(s["calls"]) == s["tool_calls"]
        # offline baseline: nothing may take ages
        assert s["duration_s"] < 30, f"{s['name']}: too slow for offline"
        # the slice must be a tiny fraction of the full schema
        assert s["slice_vs_full_pct"] < 25, (
            f"{s['name']}: slice {s['slice_vs_full_pct']}% of full — "
            "navigation is drifting toward everything-at-once")


def test_totals_bounded():
    report = bench.run_baselines()
    t = report["totals"]
    assert t["tool_calls"] <= 40, "offline scenarios grew beyond the plan's baseline"
    assert t["avg_slice_pct"] < 10
    assert t["fixture_requests"] == 21
    assert sum(s["expected_errors"] for s in report["scenarios"]) == 2


def test_bench_cli_json():
    import json
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-m", "moonmcp.bench"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[:400]
    report = json.loads(r.stdout)
    assert report["total_scenarios"] == 7


@pytest.mark.parametrize("fn", bench.ALL_SCENARIOS, ids=lambda f: f.__name__)
def test_single_scenario_reproducible(fn):
    """Same scenario, same shape of result — the plan demands the
    scenarios be reproducible one at a time too."""
    r1, r2 = fn(), fn()
    assert r1.name == r2.name
    assert r1.calls == r2.calls, "scenario is not deterministic in its call set"
    assert r1.outcomes == r2.outcomes
    assert r1.fixture_requests == r2.fixture_requests


def test_baseline_preserves_user_context_environment_and_stores(monkeypatch, tmp_path):
    import os
    from pathlib import Path

    from moonmcp import server
    from moonmcp.config import Settings
    from moonmcp.context import build_context

    monkeypatch.setenv("MOONMCP_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("MOONMCP_AUDIT_LOG", str(tmp_path / "user-audit.jsonl"))
    context = build_context(Settings(state_dir=str(tmp_path)))
    monkeypatch.setattr(server, "_CTX", context)
    user_run = context.runs.create("example.com")
    user_task = context.runs.add_task(user_run["id"], "do not modify")
    context.memory.add(kind="note", title="user data", body="preserve me", target="example.com")
    context.audit.record("sentinel")
    before_env = dict(os.environ)
    before_files = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}

    def forbid_home():
        raise AssertionError("baseline must never resolve the user's home")

    monkeypatch.setattr(Path, "home", forbid_home)
    try:
        bench.run_baselines()
        assert server.get_context() is context
        assert dict(os.environ) == before_env
        assert context.runs.task(user_task["id"])["state"] == "pending"
        assert context.runs.list_runs() == [context.runs.get(user_run["id"])]
        assert {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()} == before_files
    finally:
        for store in vars(context).values():
            close = getattr(store, "close", None)
            if callable(close):
                close()


def test_unexpected_tool_error_fails_scenario():
    with bench._Sandbox() as sandbox:
        harness = bench.Harness(sandbox, "broken", "test error detection")
        with pytest.raises(AssertionError, match="invalid_input"):
            harness.call("run_status", run_id="does-not-exist")


def test_changed_fixture_response_fails_semantic_oracle(monkeypatch):
    from moonmcp.net.http import HttpResult

    def wrong_response(self, url, *args):
        return HttpResult(url, url, 200, "fixture", [], b"ordinary page", 1)

    monkeypatch.setattr(bench._Sandbox, "_transport", wrong_response)
    with pytest.raises(AssertionError, match="one_graphql_endpoint"):
        bench.scenario_graphql_signs()
