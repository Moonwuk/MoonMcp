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

import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from ..memory import MemoryStore
from ..strix_adapted import AgentGraph

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
#  Types
# ──────────────────────────────────────────────────────────────────────

AgentStatus = str  # "running" | "waiting" | "completed" | "crashed"
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


class _AgentResult:
    """Concrete default implementation of ``AgentResult``."""

    __slots__ = ("success", "findings", "summary")

    def __init__(self, success: bool = True, findings: list[dict] | None = None,
                 summary: str = "") -> None:
        self.success = success
        self.findings = findings or []
        self.summary = summary

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
        trust: str = "curated",
        tags: str = "",
    ) -> int:
        """Write a finding/observation to the shared memory hub.

        Returns the memory item id. Other agents can retrieve this via
        ``agent.search(title)`` or ``agent.recall()``.
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
        """Retrieve recent items from the memory hub (optionally filtered by kind)."""
        return self.memory.recent(limit=limit, kind=kind)

    @property
    def findings(self) -> list[dict[str, Any]]:
        """Findings this agent has shared (cached list)."""
        return list(self._findings_cache)

    # ── lifecycle ───────────────────────────────────────────────────────

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
        for action in actions:
            try:
                action(self)
            except Exception:
                logger.exception("Recon action failed for %s", self.agent_id)

        summary = (f"Recon on {self.target}: "
                  f"{len(self.subdomains)} subdomains, "
                  f"{len(self.technologies)} technologies, "
                  f"{len(self.endpoints)} endpoints")

        return _AgentResult(
            success=True,
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
        for probe in probes:
            try:
                probe(self)
            except Exception:
                logger.exception("Exploit probe failed for %s", self.agent_id)

        summary = (f"Exploit on {self.target}: "
                  f"{len(self.probes_run)} probes run, "
                  f"{len(self.confirmed)} confirmed")

        return _AgentResult(
            success=True,
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
            "timestamp": datetime.now(UTC).isoformat(),
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
        for action in actions:
            try:
                action(self)
            except Exception:
                logger.exception("Post-ex action failed for %s", self.agent_id)

        # Build a simple report from findings.
        self.report = self._build_report(all_findings)

        self.share(
            f"Report: {self.target}",
            body=self.report,
            trust="curated",
            tags="post-ex,report",
        )

        return _AgentResult(
            success=True,
            findings=list(self._findings_cache),
            summary=f"Post-ex on {self.target}: {len(self.chains)} chains, report generated",
        )

    def _build_report(self, findings: list[dict[str, Any]]) -> str:
        """Generate a markdown summary from shared findings."""
        lines = [
            f"# Post-Exploitation Report: {self.target}",
            "",
            f"Generated: {datetime.now(UTC).isoformat()}",
            f"Agent: {self.agent_id}",
            f"Total findings: {len(findings)}",
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
                lines.append(f"- **[{sev}]** {item.get('title', 'untitled')}")
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
            "timestamp": datetime.now(UTC).isoformat(),
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
        """Run all child agents sequentially and return their results."""
        results: list[_AgentResult] = []
        for child in self.children:
            if self.graph.budget_stopped:
                logger.warning("Budget stop active — skipping %s", child.agent_id)
                break
            child.set_status("running")
            try:
                result = child.run()
                child.complete()
                results.append(result)
            except Exception:
                logger.exception("Child agent %s crashed", child.agent_id)
                child.crash()
                results.append(_AgentResult(
                    success=False, summary=f"{child.role} agent crashed"))
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
        if self.children:
            results = self.run_all()
            completed = sum(1 for r in results if r.success)
            summary = (f"Orchestration of {self.target}: "
                      f"{completed}/{len(results)} agents completed")
        else:
            summary = (f"Orchestrator {self.agent_id} ready on {self.target} "
                      f"(no children spawned yet)")

        return _AgentResult(success=True, summary=summary)

    def list_children(self) -> list[dict[str, Any]]:
        """Return a summary of all spawned child agents."""
        return [c.to_dict() for c in self.children]

    def render_tree(self) -> str:
        """Render the full agent tree (delegates to AgentGraph)."""
        return self.graph.render_tree(highlight=self.agent_id)