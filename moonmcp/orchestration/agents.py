"""Agent classes for multi-agent orchestration in MoonMCP.

Each agent wraps a *role* (recon / exploit / post-ex), a *status* tracked in
the shared ``AgentGraph``, a *target*, and a reference to the ``MemoryStore``
so findings can be written and read across agents.

Usage::

    from moonmcp.orchestration import ReconAgent, OrchestratorAgent

    recon = ReconAgent(target="example.com", memory=store, graph=graph)
    recon.register()
    recon.run()          # subclass-specific recon logic
    recon.share("Subdomain list", "api.example.com, dev.example.com")
    recon.complete()

    orch = OrchestratorAgent(target="example.com", memory=store, graph=graph)
    orch.register()
    child = orch.spawn_child("recon")  # returns a ReconAgent at depth 1
"""

from __future__ import annotations

import inspect
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol

from ..memory import MemoryStore
from ..outcomes import failure
from ..strix_adapted import AgentGraph

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
#  Types
# ──────────────────────────────────────────────────────────────────────

AgentStatus = str  # "running" | "waiting" | "completed" | "failed" | "blocked" | "crashed"
AgentRole = str    # "recon" | "exploit" | "post-ex" | "orchestrator"

MAX_SPAWN_DEPTH = 1

# Map role → default kind prefix used when writing to the memory hub.
_ROLE_KIND: dict[str, str] = {
    "recon": "observation",
    "exploit": "finding",
    "post-ex": "knowledge",
    "orchestrator": "note",
}


# ──────────────────────────────────────────────────────────────────────
#  Result protocol (lightweight, returned by ``run``)
# ──────────────────────────────────────────────────────────────────────

class AgentResult(Protocol):
    """Structured result returned by ``agent.run()``."""
    success: bool
    findings: list[dict[str, Any]]
    summary: str
    state: str
    errors: list[dict[str, Any]]


class _AgentResult:
    """Concrete default implementation of ``AgentResult``."""

    __slots__ = ("success", "findings", "summary", "state", "errors")

    def __init__(self, success: bool = True, findings: list[dict] | None = None,
                 summary: str = "", *, state: str | None = None,
                 errors: list[dict[str, Any]] | None = None) -> None:
        self.success = success
        self.findings = findings or []
        self.summary = summary
        self.state = state or ("completed" if success else "failed")
        self.errors = errors or []

    def __repr__(self) -> str:
        return (f"_AgentResult(success={self.success}, "
                f"findings={len(self.findings)}, summary={self.summary!r})")


# ──────────────────────────────────────────────────────────────────────
#  BaseAgent
# ──────────────────────────────────────────────────────────────────────

class BaseAgent:
    """Base class for all orchestration agents.

    Attributes
    ----------
    agent_id : str       — unique identifier (auto-generated uuid4 prefix)
    role : str           — "recon" | "exploit" | "post-ex" | "orchestrator"
    status : str         — current lifecycle status
    target : str         — the host / URL / domain this agent works on
    memory : MemoryStore — shared persistent store for cross-agent findings
    graph : AgentGraph   — shared agent-tree tracker
    parent_id : str|None — parent agent id (None for root)
    depth : int          — spawn depth (0 = root, 1 = spawned child)
    """

    role: AgentRole = "base"

    def __init__(
        self,
        target: str,
        *,
        memory: MemoryStore | None = None,
        graph: AgentGraph | None = None,
        agent_id: str | None = None,
        parent_id: str | None = None,
        depth: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.agent_id = agent_id or f"agent-{uuid.uuid4().hex[:12]}"
        self.target = target
        self.memory = memory or MemoryStore()
        self.graph = graph or AgentGraph()
        self.parent_id = parent_id
        self.depth = depth
        self.status: AgentStatus = "waiting"
        self.metadata: dict[str, Any] = metadata or {}
        self._findings_cache: list[dict[str, Any]] = []

    # ── agent_tree integration ──────────────────────────────────────────

    def register(self) -> dict[str, Any]:
        """Register this agent in the shared agent graph."""
        self.graph.register(self.agent_id, self.name, parent=self.parent_id)
        self.graph.set_metadata(self.agent_id, "role", self.role)
        self.graph.set_metadata(self.agent_id, "target", self.target)
        self.graph.set_metadata(self.agent_id, "depth", self.depth)
        self.status = "running"
        self.graph.update_status(self.agent_id, "running")
        logger.info("Agent %s (%s) registered for target %s",
                     self.agent_id, self.role, self.target)
        return {"registered": True, "agent_id": self.agent_id, "role": self.role}

    def set_status(self, status: AgentStatus) -> dict[str, Any]:
        """Update this agent's status in the graph."""
        self.status = status
        self.graph.update_status(self.agent_id, status)
        return {"agent_id": self.agent_id, "status": status}

    def complete(self) -> dict[str, Any]:
        """Mark this agent as completed."""
        return self.set_status("completed")

    def crash(self) -> dict[str, Any]:
        """Mark this agent as crashed."""
        return self.set_status("crashed")

    # ── shared memory integration ────────────────────────────────────────

    @property
    def name(self) -> str:
        """Display name for the agent graph."""
        return f"{self.role}-agent"

    def share(
        self,
        title: str,
        body: str = "",
        *,
        severity: str | None = None,
        trust: str = "untrusted",
        provenance: str = "inferred",
        tags: str = "",
    ) -> int:
        """Write a finding/observation to the shared memory hub.

        Returns the memory item id. Other agents can retrieve this via
        ``agent.search(title)`` or ``agent.recall()``.
        Agent-authored content defaults to untrusted/inferred; curated trust
        requires an explicit review by the caller, never just an agent role.
        """
        kind = _ROLE_KIND.get(self.role, "note")
        item_id = self.memory.add(
            kind=kind,
            title=title,
            body=body,
            target=self.target,
            severity=severity,
            source=self.agent_id,
            trust=trust,
            provenance=provenance,
            tags=tags,
        )
        self._findings_cache.append({
            "memory_id": item_id,
            "title": title,
            "severity": severity,
        })
        logger.debug("Agent %s shared: %s (id=%d)", self.agent_id, title, item_id)
        return item_id

    def search(
        self,
        query: str = "",
        *,
        kind: str | None = None,
        trust: str | None = None,
        target: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search the shared memory hub for findings from any agent."""
        return self.memory.search(
            query,
            kind=kind,
            trust=trust,
            target=target or self.target,
            limit=limit,
        )

    def recall(self, *, kind: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Retrieve recent items for this target (optionally filtered by kind)."""
        return self.memory.search("", target=self.target, limit=limit, kind=kind)

    @property
    def findings(self) -> list[dict[str, Any]]:
        """Findings this agent has shared (cached list)."""
        return list(self._findings_cache)

    # ── lifecycle ───────────────────────────────────────────────────────

    def _run_callbacks(self, callbacks: list[Callable]) -> _AgentResult:
        """Run synchronous actions in order, stopping on error or budget stop.

        ``None`` remains a valid result for callbacks that update this agent.
        Top-level execution errors are failures; negative detector verdicts are
        valid results. No callback is retried automatically.
        """
        if self.graph.budget_stopped:
            return _AgentResult(success=False, state="blocked", errors=[{
                "error": "budget_exhausted", "skipped_actions": len(callbacks),
                "retryable": False,
            }])
        for index, callback in enumerate(callbacks):
            error: dict[str, Any] | None = None
            state = "failed" if index == 0 else "partial"
            stopped_before_action = self.graph.budget_stopped
            if stopped_before_action:
                error = {"error": "budget_exhausted"}
                state = "blocked" if index == 0 else "partial"
            else:
                try:
                    value = callback(self)
                    if inspect.isawaitable(value):
                        # This API is synchronous. Do not silently discard an
                        # async tool call and report that it executed.
                        if inspect.iscoroutine(value):
                            value.close()
                        elif hasattr(value, "cancel"):
                            value.cancel()
                        error = {"error": "async_callback_unsupported",
                                 "recovery": "Await the tool in an asynchronous driver; "
                                             "run() accepts synchronous callbacks."}
                    else:
                        failed = failure(value)
                        if failed is not None:
                            error = {"error": failed.code, "recovery": failed.recovery}
                        elif (value is False or getattr(value, "success", None) is False
                              or isinstance(value, dict) and (
                                  value.get("success") is False or value.get("ok") is False
                                  or value.get("state") in {"failed", "partial", "blocked",
                                                            "cancelled", "unknown"})):
                            error = {"error": "action_failed"}
                        returned_state = (value.get("state") if isinstance(value, dict)
                                          else getattr(value, "state", None))
                        if returned_state == "unknown":
                            state = "unknown"
                except Exception as exc:
                    logger.exception("Action %d failed for %s", index, self.agent_id)
                    error = {"error": "callback_exception", "exception_type": type(exc).__name__}
            if error is not None:
                skipped = len(callbacks) - index - (0 if stopped_before_action else 1)
                error.update(action_index=index, skipped_actions=skipped,
                             retryable=False)
                return _AgentResult(success=False, state=state, errors=[error])
        return _AgentResult()

    def run(self) -> _AgentResult:
        """Execute the agent's task. Override in subclasses."""
        logger.info("Agent %s run() — base implementation (no-op)", self.agent_id)
        return _AgentResult(success=True, summary=f"{self.role} agent ran (no-op)")

    # ── introspection ───────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize agent state for snapshot/logging."""
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "status": self.status,
            "target": self.target,
            "parent_id": self.parent_id,
            "depth": self.depth,
            "findings_count": len(self._findings_cache),
            "metadata": dict(self.metadata),
        }

    def __repr__(self) -> str:
        return (f"<{self.__class__.__name__} id={self.agent_id} "
                f"role={self.role} status={self.status} target={self.target}>")


# ──────────────────────────────────────────────────────────────────────
#  ReconAgent
# ──────────────────────────────────────────────────────────────────────

class ReconAgent(BaseAgent):
    """Reconnaissance agent — subdomain enum, fingerprint, crawl.

    Typical actions:
    - enumerate_subdomains(target)
    - fingerprint(target)
    - crawl(target)
    - dns_lookup / tls_inspect
    - share observations to the memory hub
    """

    role: AgentRole = "recon"

    def __init__(self, target: str, **kwargs: Any) -> None:
        super().__init__(target, **kwargs)
        self.subdomains: list[str] = []
        self.technologies: list[str] = []
        self.endpoints: list[str] = []

    def run(self) -> _AgentResult:
        """Execute recon logic.

        This implementation stores a structured observation in shared memory
        and returns a summary. Subclasses or callers can override ``run`` to
        inject real probe callbacks.
        """
        logger.info("ReconAgent %s starting recon on %s", self.agent_id, self.target)

        # Store a recon-start observation so downstream agents know recon ran.
        self.share(
            f"Recon started: {self.target}",
            body=f"Agent {self.agent_id} began reconnaissance on {self.target}",
            tags="recon,status",
        )

        # If action callbacks were injected via metadata, run them.
        actions: list[Callable] = self.metadata.get("actions", [])
        outcome = self._run_callbacks(actions)

        summary = (f"Recon on {self.target}: "
                  f"{len(self.subdomains)} subdomains, "
                  f"{len(self.technologies)} technologies, "
                  f"{len(self.endpoints)} endpoints; state={outcome.state}")

        return _AgentResult(
            success=outcome.success,
            state=outcome.state,
            errors=outcome.errors,
            findings=list(self._findings_cache),
            summary=summary,
        )

    def add_subdomain(self, subdomain: str) -> None:
        """Record a discovered subdomain and share it to memory."""
        self.subdomains.append(subdomain)
        self.share(
            f"Subdomain: {subdomain}",
            body=f"Discovered subdomain {subdomain} for {self.target}",
            tags="recon,subdomain",
        )

    def add_technology(self, tech: str) -> None:
        """Record a detected technology and share it to memory."""
        self.technologies.append(tech)
        self.share(
            f"Technology: {tech}",
            body=f"Detected {tech} on {self.target}",
            tags="recon,technology",
        )

    def add_endpoint(self, endpoint: str) -> None:
        """Record a discovered endpoint and share it to memory."""
        self.endpoints.append(endpoint)
        self.share(
            f"Endpoint: {endpoint}",
            body=f"Discovered endpoint {endpoint} on {self.target}",
            tags="recon,endpoint",
        )


# ──────────────────────────────────────────────────────────────────────
#  ExploitAgent
# ──────────────────────────────────────────────────────────────────────

class ExploitAgent(BaseAgent):
    """Exploitation agent — sqli, xss, ssrf, idor probes.

    Reads recon observations from the shared memory hub (produced by
    ReconAgent) and runs injection / access-control probes against
    discovered endpoints.
    """

    role: AgentRole = "exploit"

    def __init__(self, target: str, **kwargs: Any) -> None:
        super().__init__(target, **kwargs)
        self.probes_run: list[dict[str, Any]] = []
        self.confirmed: list[dict[str, Any]] = []

    def run(self) -> _AgentResult:
        """Execute exploit logic.

        Pulls recon findings from memory, then runs any injected probe
        callbacks.
        """
        logger.info("ExploitAgent %s starting exploitation on %s",
                     self.agent_id, self.target)

        # Pull recon observations from the memory hub (shared by ReconAgent).
        recon_data = self.search("", kind="observation", target=self.target, limit=50)
        self.metadata["recon_observations"] = recon_data

        self.share(
            f"Exploit phase started: {self.target}",
            body=f"Agent {self.agent_id} began exploitation on {self.target} "
                 f"with {len(recon_data)} recon observations",
            tags="exploit,status",
        )

        # Run injected probe callbacks.
        probes: list[Callable] = self.metadata.get("probes", [])
        outcome = self._run_callbacks(probes)

        summary = (f"Exploit on {self.target}: "
                  f"{len(self.probes_run)} probes run, "
                  f"{len(self.confirmed)} confirmed; state={outcome.state}")

        return _AgentResult(
            success=outcome.success,
            state=outcome.state,
            errors=outcome.errors,
            findings=list(self._findings_cache),
            summary=summary,
        )

    def record_probe(self, probe_type: str, target_url: str,
                     result: str, confirmed: bool = False) -> None:
        """Record a probe result and share confirmed findings to memory."""
        entry = {
            "type": probe_type,
            "url": target_url,
            "result": result,
            "confirmed": confirmed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.probes_run.append(entry)

        severity = "high" if confirmed else "info"
        self.share(
            f"Probe: {probe_type} on {target_url}",
            body=f"Result: {result}\nConfirmed: {confirmed}",
            severity=severity,
            tags=f"exploit,{probe_type}",
        )

        if confirmed:
            self.confirmed.append(entry)


# ──────────────────────────────────────────────────────────────────────
#  PostExAgent
# ──────────────────────────────────────────────────────────────────────

class PostExAgent(BaseAgent):
    """Post-exploitation agent — chain findings, escalate, generate report.

    Reads confirmed findings from the memory hub (produced by ExploitAgent)
    and produces a consolidated report / escalation analysis.
    """

    role: AgentRole = "post-ex"

    def __init__(self, target: str, **kwargs: Any) -> None:
        super().__init__(target, **kwargs)
        self.chains: list[dict[str, Any]] = []
        self.report: str = ""

    def run(self) -> _AgentResult:
        """Execute post-exploitation logic.

        Pulls all findings from memory, builds chains, and generates a
        summary report.
        """
        logger.info("PostExAgent %s starting post-ex on %s",
                     self.agent_id, self.target)

        # Pull all findings and observations from the memory hub.
        all_findings = self.search("", target=self.target, limit=200)
        self.metadata["all_findings"] = all_findings

        self.share(
            f"Post-ex phase started: {self.target}",
            body=f"Agent {self.agent_id} began post-exploitation on {self.target} "
                 f"with {len(all_findings)} total findings",
            tags="post-ex,status",
        )

        # Run injected post-ex callbacks.
        actions: list[Callable] = self.metadata.get("actions", [])
        outcome = self._run_callbacks(actions)

        # Build a simple report from findings.
        self.report = self._build_report(all_findings)
        if not outcome.success:
            self.report += (f"\n\n## Incomplete execution\n\nState: {outcome.state}. "
                            "Later actions were skipped; reconcile the reported errors before retrying.")

        self.share(
            f"Report: {self.target}",
            body=self.report,
            tags="post-ex,report",
        )

        return _AgentResult(
            success=outcome.success,
            state=outcome.state,
            errors=outcome.errors,
            findings=list(self._findings_cache),
            summary=f"Post-ex on {self.target}: {len(self.chains)} chains, "
                    f"report generated; state={outcome.state}",
        )

    def _build_report(self, findings: list[dict[str, Any]]) -> str:
        """Generate a markdown summary from shared findings."""
        lines = [
            f"# Post-Exploitation Report: {self.target}",
            "",
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            f"Agent: {self.agent_id}",
            f"Total memory items: {len(findings)}",
            "",
        ]

        # Group by kind.
        by_kind: dict[str, list[dict]] = {}
        for f in findings:
            by_kind.setdefault(f.get("kind", "unknown"), []).append(f)

        for kind in sorted(by_kind):
            lines.append(f"## {kind.title()} ({len(by_kind[kind])})")
            lines.append("")
            for item in by_kind[kind]:
                sev = item.get("severity") or "—"
                lines.append(f"- **[{sev}]** {item.get('title', 'untitled')} "
                             f"(trust: {item.get('trust', 'untrusted')})")
            lines.append("")

        if self.chains:
            lines.append(f"## Exploit Chains ({len(self.chains)})")
            lines.append("")
            for i, chain in enumerate(self.chains, 1):
                lines.append(f"### Chain {i}")
                lines.append(chain.get("description", ""))
                lines.append("")

        return "\n".join(lines)

    def add_chain(self, description: str, steps: list[str],
                  severity: str = "high") -> None:
        """Record an exploit chain and share it to memory."""
        chain = {
            "description": description,
            "steps": steps,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.chains.append(chain)
        self.share(
            f"Chain: {description}",
            body="\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)),
            severity=severity,
            tags="post-ex,chain",
        )


# ──────────────────────────────────────────────────────────────────────
#  OrchestratorAgent
# ──────────────────────────────────────────────────────────────────────

class OrchestratorAgent(BaseAgent):
    """Orchestrator agent — spawns and coordinates child agents.

    Can spawn child agents up to ``max_spawn_depth=1`` (i.e. the orchestrator
    is at depth 0, its children are at depth 1; children cannot spawn further).
    """

    role: AgentRole = "orchestrator"

    def __init__(self, target: str, **kwargs: Any) -> None:
        super().__init__(target, **kwargs)
        self.children: list[BaseAgent] = []

    def spawn_child(self, role: str, **kwargs: Any) -> BaseAgent:
        """Spawn a child agent of the given role.

        Parameters
        ----------
        role : "recon" | "exploit" | "post-ex"
        **kwargs : passed to the child agent constructor (target, memory,
                   graph are auto-set from the orchestrator's values).

        Returns
        -------
        The spawned child agent (already registered in the graph).

        Raises
        ------
        ValueError
            If ``role`` is unknown or spawn depth would exceed
            ``MAX_SPAWN_DEPTH``.
        """
        if self.depth >= MAX_SPAWN_DEPTH:
            raise ValueError(
                f"Cannot spawn child at depth {self.depth + 1}: "
                f"max_spawn_depth={MAX_SPAWN_DEPTH}"
            )

        role_map: dict[str, type[BaseAgent]] = {
            "recon": ReconAgent,
            "exploit": ExploitAgent,
            "post-ex": PostExAgent,
        }

        cls = role_map.get(role)
        if cls is None:
            raise ValueError(f"Unknown agent role: {role!r}. "
                             f"Choose from {list(role_map)}")

        # Inherit memory + graph from orchestrator, set parent + depth.
        child = cls(
            target=kwargs.pop("target", self.target),
            memory=kwargs.pop("memory", self.memory),
            graph=kwargs.pop("graph", self.graph),
            parent_id=self.agent_id,
            depth=self.depth + 1,
            **kwargs,
        )
        child.register()
        self.children.append(child)

        logger.info("Orchestrator %s spawned %s agent %s",
                     self.agent_id, role, child.agent_id)
        return child

    def run_all(self) -> list[_AgentResult]:
        """Run the sequential workflow, preserving failed and skipped outcomes.

        A failed child blocks subsequent phases: they must not assume their
        prerequisite completed. Every child gets a result, including skipped work.
        """
        results: list[_AgentResult] = []
        blocked_reason: str | None = None
        for child in self.children:
            if self.graph.budget_stopped:
                blocked_reason = "budget_exhausted"
            if blocked_reason is not None:
                child.set_status("blocked")
                results.append(_AgentResult(
                    success=False, state="blocked",
                    summary=f"{child.role} agent skipped: {blocked_reason}",
                    errors=[{"error": blocked_reason, "agent_id": child.agent_id,
                             "retryable": False}],
                ))
                continue
            child.set_status("running")
            try:
                result = child.run()
                if result.success:
                    child.complete()
                else:
                    child.set_status(getattr(result, "state", "failed"))
                    blocked_reason = "prerequisite_failed"
                results.append(result)
            except Exception:
                logger.exception("Child agent %s crashed", child.agent_id)
                child.crash()
                blocked_reason = "prerequisite_failed"
                results.append(_AgentResult(
                    success=False, summary=f"{child.role} agent crashed",
                    errors=[{"error": "child_crashed", "agent_id": child.agent_id,
                             "retryable": False}]))
        return results

    def run(self) -> _AgentResult:
        """Run the full orchestration: spawn children, run them, summarize."""
        logger.info("Orchestrator %s starting on %s", self.agent_id, self.target)

        self.share(
            f"Orchestration started: {self.target}",
            body=f"Orchestrator {self.agent_id} coordinating agents on {self.target}",
            tags="orchestration,status",
        )

        # If children were pre-spawned, run them.
        success = True
        state = "ready"
        errors: list[dict[str, Any]] = []
        if self.children:
            results = self.run_all()
            completed = sum(1 for r in results if r.success)
            success = completed == len(self.children)
            state = "completed" if success else "partial" if completed else "failed"
            if results and all(getattr(r, "state", "") == "blocked" for r in results):
                state = "blocked"
            elif any(getattr(r, "state", "") == "unknown" for r in results):
                state = "unknown"
            elif any(getattr(r, "state", "") == "partial" for r in results):
                state = "partial"
            errors = [error for result in results for error in getattr(result, "errors", [])]
            summary = (f"Orchestration of {self.target}: "
                      f"{completed}/{len(self.children)} agents completed; state={state}")
        else:
            summary = (f"Orchestrator {self.agent_id} ready on {self.target} "
                      f"(no children spawned yet)")

        return _AgentResult(success=success, summary=summary, state=state, errors=errors)

    def list_children(self) -> list[dict[str, Any]]:
        """Return a summary of all spawned child agents."""
        return [c.to_dict() for c in self.children]

    def render_tree(self) -> str:
        """Render the full agent tree (delegates to AgentGraph)."""
        return self.graph.render_tree(highlight=self.agent_id)
