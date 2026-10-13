#!/usr/bin/env python3
"""Smoke test for the orchestration module — import, create, register, status, list."""

import sys

sys.path.insert(0, "/home/mex/Desktop/hermes_pipeline/MoonMcp")

from moonmcp.memory import MemoryStore
from moonmcp.orchestration import (
    ExploitAgent,
    OrchestratorAgent,
    PostExAgent,
    ReconAgent,
)
from moonmcp.orchestration.agents import MAX_SPAWN_DEPTH
from moonmcp.strix_adapted import AgentGraph


def main() -> int:
    # ── 1. Import ──────────────────────────────────────────────────────
    print("[1] Import: OK")

    # ── 2. Create agents + shared infra ────────────────────────────────
    store = MemoryStore()          # in-memory shared hub
    graph = AgentGraph()           # shared agent tree

    recon = ReconAgent(target="example.com", memory=store, graph=graph)
    exploit = ExploitAgent(target="example.com", memory=store, graph=graph)
    postex = PostExAgent(target="example.com", memory=store, graph=graph)
    orch = OrchestratorAgent(target="example.com", memory=store, graph=graph)

    print(f"[2] Create: {recon}")
    print(f"    {exploit}")
    print(f"    {postex}")
    print(f"    {orch}")

    # ── 3. Register ────────────────────────────────────────────────────
    recon.register()
    exploit.register()
    postex.register()
    orch.register()
    print("[3] Register: all registered")

    # ── 4. Status ──────────────────────────────────────────────────────
    r = recon.set_status("running")
    e = exploit.set_status("waiting")
    p = postex.set_status("completed")
    print(f"[4] Status: recon={r['status']}, exploit={e['status']}, postex={p['status']}")

    # ── 5. List (render_tree) ──────────────────────────────────────────
    tree = graph.render_tree()
    print(f"[5] List:\n{tree}")

    # ── 6. Orchestrator spawn_child ────────────────────────────────────
    child_recon = orch.spawn_child("recon")
    print(f"[6] Spawn: {child_recon} (depth={child_recon.depth})")

    # ── 7. Max spawn depth enforcement ─────────────────────────────────
    # Only OrchestratorAgent has spawn_child; ReconAgent/ExploitAgent/PostExAgent
    # do NOT, which enforces depth=1 at the type level. OrchestratorAgent at
    # depth>=MAX_SPAWN_DEPTH raises ValueError.
    try:
        child_recon.spawn_child("exploit")  # type: ignore[attr-defined]
        print("[7] MaxSpawnDepth: FAILED — no error raised")
        return 1
    except (AttributeError, ValueError) as exc:
        print(f"[7] MaxSpawnDepth: OK — {type(exc).__name__}: {exc}")

    # Also verify the OrchestratorAgent's own depth guard.
    deep_orch = OrchestratorAgent(
        target="example.com", memory=store, graph=graph, depth=MAX_SPAWN_DEPTH)
    deep_orch.register()
    try:
        deep_orch.spawn_child("recon")
        print("[7b] Orchestrator depth guard: FAILED — no error raised")
        return 1
    except ValueError as exc:
        print(f"[7b] Orchestrator depth guard: OK — {exc}")

    # ── 8. Share findings through memory ───────────────────────────────
    mid = recon.share("Subdomain found", "dev.example.com", tags="recon")
    results = exploit.search("Subdomain", target="example.com")
    print(f"[8] Share/Search: recon shared id={mid}, exploit found {len(results)} item(s)")
    assert len(results) >= 1, "Expected at least 1 result"

    # ── 9. run() lifecycle ─────────────────────────────────────────────
    recon_result = recon.run()
    exploit_result = exploit.run()
    postex_result = postex.run()
    print(f"[9] Run: recon={recon_result.summary}")
    print(f"    exploit={exploit_result.summary}")
    print(f"    post-ex={postex_result.summary}")

    # ── 10. Orchestrator run_all + render_tree ─────────────────────────
    orch_results = orch.run_all()
    print(f"[10] run_all: {len(orch_results)} children ran")
    print(f"     Tree:\n{orch.render_tree()}")

    # ── 11. to_dict ────────────────────────────────────────────────────
    d = recon.to_dict()
    print(f"[11] to_dict: {d}")

    # ── 12. budget_stop ────────────────────────────────────────────────
    graph.trigger_budget_stop()
    print(f"[12] budget_stop: budget_stopped={graph.budget_stopped}")

    # ── 13. PostEx report ───────────────────────────────────────────────
    postex.add_chain("SQLi → RCE chain", ["sqli on /search", "extract creds", "RCE via xp_cmdshell"], "critical")
    report = postex.report
    assert "Post-Exploitation Report" in report
    print(f"[13] PostEx report: {len(report)} chars, has title")

    print("\n✅ All tests passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())