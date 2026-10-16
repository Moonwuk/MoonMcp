"""Direct control interface for the fixed, opt-in local research recipe."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .. import research
from ..context import AppContext
from . import local_registration


def register(mcp: Any, safe_tool: Callable, get_context: Callable[[], AppContext]) -> dict[str, Callable]:
    exported: dict[str, Callable] = {}
    local = local_registration(mcp, safe_tool, exported)

    @local
    async def research_environment(action: str = "describe", capsule: dict | None = None,
                                   execute: bool = False, run_id: str | None = None,
                                   artifact_id: int | None = None) -> dict:
        """Describe/replay/cleanup the builtin SQLite HTTP research fixture.

        Describe returns portable capsules and requirements without side effects.
        Replay requires a capsule from describe and execute=true; it creates fresh
        accounts/data through normal HTTP routes, verifies, then removes resources.
        Requires persistent state and a preloaded pinned image on local Linux Docker.
        Cleanup accepts a run_id and research_resource artifact_id after the worker
        lease expires. Unknown work is never automatically replayed. This is a
        synthetic regression fixture, not a general project runner or discovery benchmark.
        Call directly, outside run_execute. Never accepts commands or target URLs.
        """
        if action == "describe":
            return research.describe()
        if action == "replay":
            if capsule is None:
                raise ValueError("replay requires a capsule from describe")
            return await research.replay(get_context().runs, capsule, execute=execute)
        if action == "cleanup":
            if not run_id or artifact_id is None:
                raise ValueError("cleanup requires run_id and research_resource artifact_id")
            return await research.cleanup(get_context().runs, run_id, artifact_id)
        raise ValueError("action must be describe, replay or cleanup")

    return exported
