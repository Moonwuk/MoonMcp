"""Runs tool family. Public signatures and payloads remain compatible."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..context import AppContext
from ..runs import RunBudget, seed_assessment
from . import local_registration


def register(mcp: Any, safe_tool: Callable, get_context: Callable[[], AppContext]) -> dict[str, Callable]:
    """Bind tools to this server; imports do not register or create context."""
    exported: dict[str, Callable] = {}
    local = local_registration(mcp, safe_tool, exported)

    @local
    async def run_start(target: str, focus: str = "", max_requests: int = 1000,
                        max_tool_calls: int = 250, max_intrusive_calls: int = 25) -> dict:
        """Start a persistent, resumable assessment and seed its role-based task graph.

        This creates no network traffic, but the target must already be authorised in
        MoonMCP scope. Budgets are hard counters enforced by `run_usage`; state
        survives restarts when MOONMCP_STATE_DIR is configured.
        """

        ctx = get_context()
        normalised = ctx.scope.check(target)
        budget = RunBudget(max_requests=max_requests, max_tool_calls=max_tool_calls,
                           max_intrusive_calls=max_intrusive_calls)
        run = ctx.runs.create(normalised, focus=focus, budget=budget)
        tasks = seed_assessment(ctx.runs, run["id"])
        ctx.audit.record("run_started", tool="run_start", target=normalised,
                         decision="allow", run_id=run["id"])
        return {"run": ctx.runs.get(run["id"]), "seeded_tasks": tasks,
                "next": ctx.runs.next_task(run["id"])}

    @local
    async def run_status(run_id: str, include_events: bool = False) -> dict:
        """Return one assessment's state, budgets, task counts and coverage."""

        ctx = get_context()
        out = {"run": ctx.runs.get(run_id), "tasks": ctx.runs.tasks(run_id),
               "next": ctx.runs.next_task(run_id)}
        if include_events:
            out["events"] = ctx.runs.events(run_id)
        return out

    @local
    async def run_list(state: str | None = None, limit: int = 50) -> dict:
        """List recent persistent assessments, optionally filtered by run state."""

        runs = get_context().runs.list_runs(state=state, limit=limit)
        return {"runs": runs, "count": len(runs)}

    @local
    async def run_control(run_id: str, action: str) -> dict:
        """Pause, resume, cancel or fail an assessment without losing its state."""

        states = {"pause": "paused", "resume": "running", "cancel": "cancelled",
                  "fail": "failed"}
        if action not in states:
            raise ValueError("action must be pause, resume, cancel, or fail")
        return {"run": get_context().runs.set_state(run_id, states[action])}

    @local
    async def run_task_add(run_id: str, title: str, role: str = "coordinator",
                           priority: int = 50, depends_on: int | None = None,
                           detail: str = "") -> dict:
        """Add a task to a run's dependency graph for a specialist agent."""

        task = get_context().runs.add_task(run_id, title, role=role, priority=priority,
                                          depends_on=depends_on, detail=detail)
        return {"task": task}

    @local
    async def run_task_update(task_id: int, state: str, result: str = "",
                              owner: str | None = None, claim_token: str | None = None) -> dict:
        """Move a run task through its lifecycle and attach its result summary."""

        return {"task": get_context().runs.update_task(task_id, state, result=result,
                                                       owner=owner, claim_token=claim_token)}

    @local
    async def run_next(run_id: str) -> dict:
        """Return the highest-priority unblocked task for deterministic coordination."""

        ctx = get_context()
        run = ctx.runs.get(run_id)
        if run["state"] != "running":
            return {"run": run, "next": None, "blocked": f"run is {run['state']}"}
        return {"run": run, "next": ctx.runs.next_task(run_id)}

    @local
    async def run_coverage_update(run_id: str, item: str, status: str,
                                  evidence: str = "") -> dict:
        """Upsert an assessment coverage item and its evidence reference."""

        ctx = get_context()
        entry = ctx.runs.set_coverage(run_id, item, status, evidence=evidence)
        return {"coverage_item": entry, "summary": ctx.runs.coverage_summary(run_id)}

    @local
    async def run_usage(run_id: str, requests: int = 0, tool_calls: int = 0,
                        intrusive_calls: int = 0) -> dict:
        """Atomically consume run budgets; refuse increments beyond a hard limit."""

        return {"run": get_context().runs.consume(
            run_id, requests=requests, tool_calls=tool_calls,
            intrusive_calls=intrusive_calls,
        )}

    @local
    async def run_artifact_add(run_id: str, kind: str, name: str, content: str) -> dict:
        """Store a bounded immutable evidence artifact and return its SHA-256 reference."""

        return {"artifact": get_context().runs.add_artifact(run_id, kind, name, content)}

    @local
    async def run_artifacts(run_id: str, include_content: bool = False,
                            limit: int = 100) -> dict:
        """List a run's evidence artifacts; content is omitted unless explicitly requested."""

        artifacts = get_context().runs.artifacts(
            run_id, include_content=include_content, limit=limit,
        )
        return {"artifacts": artifacts, "count": len(artifacts)}

    @local
    async def run_finish(run_id: str, force: bool = False) -> dict:
        """Complete a run only after its tasks and coverage pass the finish gate."""

        return get_context().runs.finish(run_id, force=force)

    return exported
