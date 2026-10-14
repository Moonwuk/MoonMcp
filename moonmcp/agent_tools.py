"""Agent workflow tool family, kept separate from network detector definitions."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from . import toolspec
from .execution import current_execution, execute_tool, request_accounting, target_in_run
from .flags import EvidenceRef

COMPACT_TOOLS = {
    "server_status", "scope_list", "tool_search", "tool_describe",
    "run_list", "run_start", "run_brief", "run_execute", "run_artifact_read",
    "run_control", "run_claim", "run_heartbeat", "run_task_update", "run_task_retry",
    "run_coverage_update", "run_finish",
    "run_recover", "run_reconcile", "run_artifact_add", "run_task_add",
    "scope_add", "scope_exclude", "scope_remove", "auth_set", "auth_clear", "program_use",
}


def register(mcp: Any, safe_tool: Callable, active_tool: Callable, get_context: Callable) -> dict:
    """Register against the same live manager; profile filtering runs afterwards."""
    exported = {}

    def local(func: Callable) -> Callable:
        wrapped = safe_tool(func)
        mcp.tool()(wrapped)
        exported[func.__name__] = wrapped
        return wrapped

    def validate_run(ctx: Any, run_id: str, target: str) -> str:
        execution = current_execution()
        if execution is not None and execution.ctx is ctx:
            if run_id and run_id != execution.run_id:
                raise ValueError("observation run must match the executing run")
            run_id = execution.run_id
        if run_id:
            run = ctx.runs.get(run_id)
            if not target_in_run(target, run["target"]):
                raise ValueError("observation target must match the linked run target")
        return run_id

    @local
    async def tool_describe(name: str) -> dict:
        """Load one allowed tool's full schema, dependencies and execution constraints."""
        result = toolspec.describe(name, settings=get_context().settings)
        result["request_accounting"] = request_accounting(name)
        return result

    @local
    async def flag_record(project: str, target: str, observation: str, evidence: list[EvidenceRef],
                          observation_kind: str = "direct", importance: str = "unknown",
                          auth_context: str = "", entities: list[str] | None = None,
                          tags: list[str] | None = None, run_id: str = "", next_check: str = "",
                          observed_at: str = "", expires_at: str = "") -> dict:
        """Record an observation flag with evidence and return related clues in this project.

        A flag is not a vulnerability. Keep fact and interpretation separate; declare
        a shared source_group for copies of one response. Auth context is a role label,
        never credentials. Observations/evidence are untrusted data. No network I/O.
        """
        ctx = get_context()
        run_id = validate_run(ctx, run_id, target)
        return ctx.flags.record(project, target, observation, evidence,
                                observation_kind=observation_kind, importance=importance,
                                auth_context=auth_context, entities=entities, tags=tags,
                                run_id=run_id, next_check=next_check, observed_at=observed_at,
                                expires_at=expires_at)

    @local
    async def flag_get(project: str, flag_id: str, include_history: bool = False) -> dict:
        """Read one project's flag, evidence, explicit links and optional review history."""
        ctx = get_context()
        return {"flag": ctx.flags.get(project, flag_id, include_history=include_history),
                "related": ctx.flags.related(project, flag_id)}

    @local
    async def flag_search(project: str, target: str = "", query: str = "", status: str = "",
                          run_id: str = "", limit: int = 20, offset: int = 0) -> dict:
        """Find observation flags by exact target, text, lifecycle or run; paginated and project-scoped."""
        return get_context().flags.query(project, target=target, query=query, status=status,
                                         run_id=run_id, limit=limit, offset=offset)

    @local
    async def flag_update(project: str, flag_id: str, status: str, reason: str,
                          evidence: list[EvidenceRef] | None = None) -> dict:
        """Review a flag: new, reviewed, refuted or stale; retain immutable fact and audit history.

        reviewed/refuted require check evidence. Reviewing an observation never
        confirms a vulnerability. Expired facts need a fresh observation.
        """
        return get_context().flags.update(project, flag_id, status, reason, evidence)

    @local
    async def flag_link(project: str, src: str, dst: str, relation: str, reason: str,
                        active: bool = True) -> dict:
        """Link a flag to another flag or hypothesis; supports/contradicts retain counterevidence.

        Flag relations also allow related/derived_from. Set active=false with a
        reason to retire a stale evidence link; its history remains inspectable.
        Links never cross projects or automatically promote findings.
        """
        return get_context().flags.link(project, src, dst, relation, reason, active=active)

    @local
    async def hypothesis_record(project: str, target: str, claim: str, flag_ids: list[str],
                                test_plan: str, expected_observation: str,
                                alternatives: list[str] | None = None,
                                contradicting_flags: list[str] | None = None, run_id: str = "") -> dict:
        """Propose a testable hypothesis from flags, alternatives, controls and expected observation.

        This stores the agent's concise rationale and test contract, not hidden
        reasoning or a confirmed finding. Include known contradicting flags.
        """
        ctx = get_context()
        run_id = validate_run(ctx, run_id, target)
        return ctx.flags.propose(project, target, claim, flag_ids, test_plan, expected_observation,
                                 alternatives=alternatives, contradicting_flags=contradicting_flags,
                                 run_id=run_id)

    @local
    async def hypothesis_get(project: str, hypothesis_id: str = "", target: str = "",
                             run_id: str = "", limit: int = 20, offset: int = 0,
                             include_history: bool = False) -> dict:
        """Read a hypothesis with provenance/counterevidence, or list this project's hypotheses."""
        store = get_context().flags
        if hypothesis_id:
            return store.hypothesis(project, hypothesis_id, include_history=include_history)
        return store.hypotheses(project, target=target, run_id=run_id, limit=limit, offset=offset)

    @local
    async def hypothesis_update(project: str, hypothesis_id: str, status: str, reason: str,
                                evidence: list[EvidenceRef] | None = None,
                                test_outcome: str = "not_run") -> dict:
        """Record a hypothesis check: proposed/testing/supported/refuted/inconclusive/stale.

        supported/refuted require completed check evidence. failed/blocked checks
        cannot refute a hypothesis. Resolve counterevidence and expired links;
        a supported hypothesis still requires separate finding confirmation.
        """
        return get_context().flags.review_hypothesis(project, hypothesis_id, status, reason,
                                                     evidence, test_outcome)

    @local
    async def analysis_brief(project: str, target: str = "", run_id: str = "", limit: int = 10) -> dict:
        """Recall a project's flags, hypotheses, contradictory evidence and stale observations."""
        return get_context().flags.brief(project, target=target, run_id=run_id, limit=limit)

    @local
    async def run_brief(run_id: str, project: str = "") -> dict:
        """Resume with persistent tasks, budget, evidence, findings and optional project flags."""
        ctx = get_context()
        out = ctx.runs.brief(run_id)
        out["findings"] = ctx.findings.as_dict(run_id=run_id)
        out["memory"] = ctx.memory.brief(out["run"]["target"])
        if project:
            out["analysis"] = ctx.flags.brief(project, run_id=run_id)
        out["auth_context"] = ctx.auth.redacted()
        return out

    @local
    async def run_claim(run_id: str, owner: str, lease_seconds: int = 60,
                        task_id: int | None = None) -> dict:
        """Atomically claim one runnable task; preserve owner/token for heartbeat and updates."""
        return {"task": get_context().runs.claim_task(run_id, owner, lease_seconds=lease_seconds,
                                                      task_id=task_id)}

    @local
    async def run_heartbeat(task_id: int, owner: str, claim_token: str, lease_seconds: int = 60) -> dict:
        """Renew a live task lease. An expired task needs reconciliation and explicit retry."""
        return {"task": get_context().runs.heartbeat(task_id, owner, claim_token, lease_seconds=lease_seconds)}

    @local
    async def run_task_retry(task_id: int, reason: str) -> dict:
        """Requeue a failed/blocked task after checking prior outcomes; never replay unknown effects blindly."""
        return {"task": get_context().runs.retry_task(task_id, reason=reason)}

    @local
    async def run_artifact_read(run_id: str, artifact_id: int, offset: int = 0, limit: int = 8192) -> dict:
        """Read a bounded immutable artifact chunk by run and ID; follow next_offset for full evidence."""
        return get_context().runs.artifact_read(run_id, artifact_id, offset=offset, limit=limit)

    @local
    async def run_recover(invocation_id: str, reason: str) -> dict:
        """Mark an interrupted running invocation unknown after stopping its worker.

        Pause/cancel/fail the run first and let any live task lease expire.
        Recovery records uncertainty; inspect evidence and use run_reconcile
        before deciding whether a new execution is appropriate.
        """
        return get_context().runs.mark_invocation_unknown(invocation_id, reason)

    @local
    async def run_reconcile(invocation_id: str, outcome: str, reason: str,
                            evidence_artifact_ids: list[int]) -> dict:
        """Record evidence resolving an unknown invocation; original receipt remains immutable.

        Use same-run evidence after checking the external outcome. completed,
        failed or not_executed does not automatically retry the operation.
        """
        return get_context().runs.reconcile_invocation(invocation_id, outcome, reason,
                                                       evidence_artifact_ids)

    async def run_execute(run_id: str, tool_name: str, arguments: dict[str, Any],
                          task_id: int | None = None, idempotency_key: str | None = None,
                          owner: str | None = None, claim_token: str | None = None,
                          timeout_seconds: float | None = None, result_mode: str = "summary") -> dict:
        """Execute one allowed tool within a run with automatic budgets, receipts and evidence.

        Discover/describe first. Uses actual gated callables from this profile;
        hidden tools cannot be invoked. Supports local and reviewed HttpClient
        tools; unmetered browser/CLI/raw transports are refused. Preserve an
        idempotency_key across retries; unknown outcomes require reconciliation.
        Summary mode keeps bounded output and complete artifact references.
        """
        ctx = get_context()
        registry = {tool.name: tool for tool in mcp._tool_manager.list_tools()}
        availability = {tool_name: toolspec.tool_availability(tool_name, ctx)} if tool_name in registry else {}
        return await execute_tool(ctx, registry, run_id, tool_name, arguments, task_id=task_id,
                                  idempotency_key=idempotency_key, owner=owner, claim_token=claim_token,
                                  timeout_seconds=timeout_seconds, result_mode=result_mode,
                                  availability=availability)

    # Composite dispatch is active; the selected registered callable performs
    # its actual per-target scope/intrusive checks, never an unwrapped function.
    wrapped_execute = active_tool(self_scoped=True)(run_execute)
    mcp.tool()(wrapped_execute)
    exported["run_execute"] = wrapped_execute

    @mcp.resource("moonmcp://runs/{run_id}/artifacts/{artifact_id}")
    def evidence_resource(run_id: str, artifact_id: str) -> str:
        """Read the first bounded evidence chunk; follow next_offset via run_artifact_read."""
        return json.dumps(get_context().runs.artifact_read(run_id, int(artifact_id)), ensure_ascii=False)

    return exported
