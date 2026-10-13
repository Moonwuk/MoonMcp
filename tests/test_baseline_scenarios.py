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