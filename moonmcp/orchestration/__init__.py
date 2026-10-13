"""Multi-agent orchestration for MoonMCP.

Provides specialised agent classes (ReconAgent, ExploitAgent, PostExAgent)
that coordinate through the shared agent_tree (AgentGraph) and share findings
through the persistent memory hub (MemoryStore).

This module is self-contained — it does NOT register any MCP tools. It exposes
plain Python classes that can be imported and driven by the server, a CLI, or
an external orchestrator (e.g. Hermes delegate_task).

Architecture::

    BaseAgent
      ├── ReconAgent      — subdomain enum, fingerprint, crawl
      ├── ExploitAgent    — sqli, xss, ssrf, idor probes
      └── PostExAgent     — chain, escalate, report

    OrchestratorAgent     — spawns child agents (max_spawn_depth=1)

Coordination is via ``AgentGraph`` (register / status / list / snapshot /
budget_stop) imported from ``moonmcp.strix_adapted``. Findings are shared via
``MemoryStore`` imported from ``moonmcp.memory``.
"""

from __future__ import annotations

from .agents import (
    BaseAgent,
    ExploitAgent,
    OrchestratorAgent,
    PostExAgent,
    ReconAgent,
)

__all__ = [
    "BaseAgent",
    "ReconAgent",
    "ExploitAgent",
    "PostExAgent",
    "OrchestratorAgent",
]