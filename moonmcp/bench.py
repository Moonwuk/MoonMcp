"""Stage 0 baseline scenarios (AGENT_NAVIGATION_PLAN.md).

Reproducible, offline scenarios that measure the cost of a typical
agent navigation step *without* network or an LLM:

  calls    — how many MoonMCP tool invocations the scenario needs
  schema   — bytes of tools/list the agent would load for the slice
  duration — wall-clock of the tool calls themselves

The scenarios deliberately drive REAL tool callables (server functions
or underlying module functions) against fixture data, so the numbers
measure MoonMCP itself, not a mock of it. No scenario touches a target;
fixtures are local files/objects only.

Run:  python -m moonmcp.bench  (or pytest tests/test_baseline_scenarios.py)
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

# ──────────────────────────────────────────────────────────────────
# Measurement harness
# ──────────────────────────────────────────────────────────────────


@dataclass
class ScenarioResult:
    name: str
    description: str
    calls: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    schema_bytes: int = 0
    notes: list[str] = field(default_factory=list)


def _schema_bytes(tool_names: list[str]) -> int:
    """The context cost of the tools the scenario says it needs — the
    JSON-schema bytes of exactly those tools' definitions."""
    from .server import mcp
    tools = {t.name: t for t in mcp._tool_manager.list_tools()}
    return sum(len(json.dumps({"name": n,
                               "description": tools[n].description or "",
                               "inputSchema": tools[n].parameters}))
               for n in tool_names if n in tools)


def _full_schema_bytes() -> int:
    from .server import mcp
    tools = mcp._tool_manager.list_tools()
    return sum(len(json.dumps({"name": t.name,
                              "description": t.description or "",
                              "inputSchema": t.parameters}))
               for t in tools)


class Harness:
    """Drives real tool callables, counting every invocation."""

    def __init__(self) -> None:
        self.result: ScenarioResult | None = None
        self._t0 = 0.0

    def start(self, name: str, description: str) -> Harness:
        self.result = ScenarioResult(name=name, description=description)
        self._t0 = time.monotonic()
        return self

    def call(self, tool_name: str, coro_factory) -> object:
        """Run an async tool callable, count it, return its result."""
        assert self.result is not None
        self.result.calls.append(tool_name)
        out = asyncio.run(_run(coro_factory))
        return out

    def note(self, text: str) -> None:
        assert self.result is not None
        self.result.notes.append(text)

    def finish(self, needed_tools: list[str]) -> ScenarioResult:
        assert self.result is not None
        self.result.duration_s = time.monotonic() - self._t0
        self.result.schema_bytes = _schema_bytes(needed_tools)
        return self.result


async def _run(factory) -> object:
    return await factory()


def _run_id(created: object) -> str:
    """run_start returns {"run": {"id": ...}}."""
    if isinstance(created, dict):
        run = created.get("run")
        if isinstance(run, dict) and run.get("id"):
            return str(run["id"])
        if created.get("id"):
            return str(created["id"])
    raise AssertionError(f"unexpected run_start payload: {created!r}")


def _setup_scope() -> None:
    """Authorise the offline baseline host so run tools accept it."""
    from . import server as srv
    ctx = srv.get_context()
    try:
        ctx.scope.add("baseline.test")
    except Exception:  # noqa: BLE001 — already added
        pass


# ──────────────────────────────────────────────────────────────────
# The seven plan scenarios (offline slices only)
# ──────────────────────────────────────────────────────────────────


def scenario_new_target() -> ScenarioResult:
    """A fresh, unknown target: orient → map the surface (offline slice:
    catalog + knowledge recall; the network probes are listed as the
    would-be next step, not executed)."""
    from . import server as srv

    h = Harness().start("new_target",
                        "Orient on a fresh target: status, catalog, recall.")
    h.call("server_status", lambda: srv.server_status())
    h.call("tool_catalog", lambda: srv.tool_catalog(family="light_active"))
    h.call("memory_brief", lambda: srv.memory_brief(target="baseline.test"))
    res = h.finish(["server_status", "tool_catalog", "memory_brief",
                    "http_probe", "fingerprint", "recon_target"])
    res.notes.append("network probes (http_probe/fingerprint/recon_target) "
                     "listed but not executed — offline baseline")
    return res


def scenario_run_continuation() -> ScenarioResult:
    """Resume a persisted run: list runs, read status, ask for next task."""
    from . import server as srv

    h = Harness().start("run_continuation",
                        "Pick up an existing run: list, status, next task.")
    h.call("run_list", lambda: srv.run_list(limit=5))

    # create a scratch run to have something to continue
    store_dir = Path.home() / ".moonmcp_baseline_runs"
    store_dir.mkdir(exist_ok=True)
    import os
    os.environ.setdefault("MOONMCP_STATE_DIR", str(Path.home() / ".hermes" / "moonmcp_state"))
    created = h.call("run_start", lambda: srv.run_start(target="baseline.test",
                                                        focus="continuation probe"))
    run_id = _run_id(created)
    h.call("run_status", lambda: srv.run_status(run_id=run_id))
    h.call("run_next", lambda: srv.run_next(run_id=run_id))
    h.call("run_task_update", lambda: srv.run_task_update(task_id=1, state="running"))
    h.call("run_finish", lambda: srv.run_finish(run_id=run_id, force=True))
    res = h.finish(["run_list", "run_start", "run_status", "run_next",
                    "run_task_update", "run_finish", "memory_brief"])
    return res


def scenario_graphql_signs() -> ScenarioResult:
    """Observed GraphQL: the minimal navigation is check-then-deepen
    (offline slice: the class reference)."""
    from . import server as srv

    h = Harness().start("graphql_signs",
                        "GraphQL observed: class reference + planned deepening.")
    h.call("graphql_check", lambda: srv.graphql_check(target="https://baseline.test/graphql"))
    h.call("injection_info", lambda: srv.injection_info(injection_class="graphql"))
    res = h.finish(["graphql_check", "graphql_probe", "injection_info"])
    res.notes.append("graphql_probe listed as the deepening step; reference "
                     "lookup executed offline")
    return res


def scenario_authed_surface() -> ScenarioResult:
    """Auth + roles context: what the agent loads before IDOR work."""
    from . import server as srv

    h = Harness().start("authed_surface",
                        "Authed surface: recall + access-control class reference.")
    h.call("memory_brief", lambda: srv.memory_brief(target="baseline.test"))
    h.call("injection_info", lambda: srv.injection_info(injection_class="xss"))  # baseline class ref
    res = h.finish(["auth_set", "access_control_check", "authz_probe", "memory_brief"])
    res.notes.append("auth_set/access_control_check need live credentials — "
                     "schema cost measured, not executed")
    return res


def scenario_false_lead() -> ScenarioResult:
    """A lead that dies under validation: the plan demands the dead end be
    RECORDED, not repeated."""
    from . import server as srv

    h = Harness().start("false_lead",
                        "Lead recorded as not confirmed; lesson saved.")
    h.call("promote_lead", lambda: srv.promote_lead(
        target="baseline.test", kind="multistep_bola", severity="low",
        detail="baseline: not reproduced (control matched)",
        evidence="control == baseline", record=True))
    h.call("memory_lesson", lambda: srv.memory_lesson(action="add",
        title="baseline false-lead pattern",
        body="A lead that fails its control must be recorded, never re-fired "
             "unchanged."))
    res = h.finish(["promote_lead", "memory_lesson", "confirm_finding"])
    return res


def scenario_no_browser() -> ScenarioResult:
    """Browser-dependent step with no browser present: degrade, don't stall."""
    from . import server as srv

    h = Harness().start("no_browser",
                        "browser_open unavailable — navigate around it.")
    res_probe = h.call("analyze_js", lambda: srv.analyze_js(target="https://baseline.test/app.js"))
    if not isinstance(res_probe, dict) or res_probe.get("error"):
        h.note("analyze_js degraded the same way a missing browser would — "
               "record and continue with the static slice")
    res = h.finish(["browser_open", "analyze_js", "well_known"])
    res.notes.append("browser_open listed for schema cost only; static slice "
                     "executed offline")
    return res


def scenario_budget_exhausted() -> ScenarioResult:
    """Budget refused: record the blocked task, stop."""
    from . import server as srv

    h = Harness().start("budget_exhausted",
                        "run_usage refuses the overrun; task recorded blocked.")
    created = h.call("run_start", lambda: srv.run_start(
        target="baseline.test", focus="budget probe",
        max_requests=1, max_tool_calls=2))
    run_id = _run_id(created)
    try:
        h.call("run_usage", lambda: srv.run_usage(run_id=run_id, requests=5))
        h.note("UNEXPECTED: budget not enforced")
    except Exception as exc:  # noqa: BLE001 — the refusal is the point
        h.note(f"budget refused as designed: {type(exc).__name__}")
    res = h.finish(["run_usage", "run_task_update", "run_status"])
    return res


ALL_SCENARIOS = [
    scenario_new_target,
    scenario_run_continuation,
    scenario_graphql_signs,
    scenario_authed_surface,
    scenario_false_lead,
    scenario_no_browser,
    scenario_budget_exhausted,
]


def run_baselines() -> dict:
    """Run every scenario, return the measured report."""
    _setup_scope()
    results = [fn() for fn in ALL_SCENARIOS]
    full = _full_schema_bytes()
    report = {
        "stage": "0-baseline",
        "total_scenarios": len(results),
        "full_schema_bytes": full,
        "scenarios": [{
            "name": r.name,
            "description": r.description,
            "tool_calls": len(r.calls),
            "calls": r.calls,
            "duration_s": round(r.duration_s, 3),
            "slice_schema_bytes": r.schema_bytes,
            "slice_vs_full_pct": round(100 * r.schema_bytes / max(full, 1), 1),
            "notes": r.notes,
        } for r in results],
        "totals": {
            "tool_calls": sum(len(r.calls) for r in results),
            "duration_s": round(sum(r.duration_s for r in results), 3),
            "avg_slice_pct": round(
                sum(r.schema_bytes for r in results) / len(results) / max(full, 1) * 100, 1),
        },
    }
    return report


def main() -> int:
    import sys
    report = run_baselines()
    json.dump(report, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())