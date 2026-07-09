# Strix as an MCP tool (alongside MoonMCP)

You already run **MoonMCP** as an MCP server for your **opencode** and **hermes**
agents. This wires **Strix** ([usestrix/strix](https://github.com/usestrix/strix),
Apache-2.0 — an autonomous AI pentester that produces working PoCs) in the *same
way*: as ordinary MCP tools your agent calls. No separate window, no third app to
babysit — one agent, two toolbelts.

## The model — MoonMCP *finds*, Strix *confirms*

| | MoonMCP | Strix (via MCP) |
| --- | --- | --- |
| Role | fast, cheap, scope-first recon + **detection** → leads | autonomous **validation** → working PoC |
| Cost | deterministic, stdlib, ~free | its own LLM loop + Docker sandbox — heavy |
| Call style | many fine-grained tool calls | one coarse, focused delegation |
| Safety | scope guard on every tool | wrapper scope-checks the target first |

The agent does cheap recon with MoonMCP, decides which high-value in-scope lead
deserves proof, delegates that one task to Strix, and merges the validated finding
back into MoonMCP's `add_finding` → `triage_findings` → `report`. The
`strix-orchestration` skill (`.claude/skills/strix-orchestration/`) is the
playbook; this doc is the wiring.

## 1. Prerequisites

- **Strix** installed and on `PATH` (`strix`), with **Docker running**.
- An LLM for Strix:
  ```bash
  export STRIX_LLM="anthropic/claude-sonnet-5"   # or your provider/model
  export LLM_API_KEY="…"
  # export LLM_API_BASE="…"                       # optional (local models)
  ```
- **Scope** (so Strix inherits MoonMCP's guard — the wrapper refuses off-scope
  network targets before launching Strix):
  ```bash
  export STRIX_SCOPE="*.example.com, api.example.io"   # or reuse MOONMCP_SCOPE
  ```

## 2. The wrapper

`examples/strix_mcp/server.py` is a small MCP server exposing:

- `strix_available()` — is `strix` + Docker + the LLM env ready?
- `strix_run(target, instruction, wait=True, timeout=1800)` — scope-checks
  `target`, prepends MoonMCP's `RULES_OF_ENGAGEMENT`, runs
  `strix -n --target … --instruction-file …`, returns the parsed run (or launches
  detached when `wait=false`).
- `strix_result(run_name=None)` — read a `strix_runs/<name>` directory.

Run it standalone to sanity-check:
```bash
python examples/strix_mcp/server.py     # speaks MCP over stdio
```

## 3. Register it with your agent

Both opencode and hermes speak the standard **MCP stdio** transport, so the server
spec is the same shape — command + args + env.

**opencode** (`opencode.json` / `~/.config/opencode/opencode.json`):
```jsonc
{
  "mcp": {
    "moonmcp": {
      "type": "local",
      "command": ["moonmcp"],
      "environment": { "MOONMCP_SCOPE": "*.example.com", "MOONMCP_ALLOW_INTRUSIVE": "0" }
    },
    "strix": {
      "type": "local",
      "command": ["python", "/abs/path/examples/strix_mcp/server.py"],
      "environment": {
        "STRIX_LLM": "anthropic/claude-sonnet-5",
        "LLM_API_KEY": "…",
        "STRIX_SCOPE": "*.example.com"
      }
    }
  }
}
```

**hermes** (and any MCP client) — register the same stdio server:
```jsonc
{
  "mcpServers": {
    "strix": {
      "command": "python",
      "args": ["/abs/path/examples/strix_mcp/server.py"],
      "env": { "STRIX_LLM": "anthropic/claude-sonnet-5", "LLM_API_KEY": "…", "STRIX_SCOPE": "*.example.com" }
    }
  }
}
```
(Adapt keys to your opencode/hermes version — the essence is *command + args + env*
for an MCP stdio server.)

## 4. The loop your agent runs

1. `server_status` / `tool_catalog` (MoonMCP) → scope/program → recon → collect
   leads with `add_finding`; confirm what's cheap with `passive_scan` /
   `http_repeater` / `intruder` / `oast_*`.
2. Pick a high-value, in-scope, unconfirmed lead. Build a tight instruction (the
   observed evidence + "validate with a minimal non-destructive PoC and stop").
3. `strix_run(target, instruction)` → Strix proves it in its sandbox.
4. Record Strix's PoC via MoonMCP `add_finding`, then `triage_findings` + `report`.

## 5. Reverse direction — give Strix access to MoonMCP (strengthen it)

The wiring above lets your agent call Strix. You can also do the opposite —
**let Strix reach into MoonMCP** for the things it lacks: MoonMCP's curated
knowledge bases, the shared memory hub, the scope guard, and cheap scope-gated
recon. That grounds Strix's exploitation in real detection knowledge and shared
context instead of re-deriving everything.

Strix has **no MCP client**, but it *does* have a shell/command tool and a Python
runtime — so expose MoonMCP through those:

- **CLI bridge (from Strix's shell tool):**
  ```bash
  moonmcp call injection_info --json '{"injection_class":"ssti"}'
  moonmcp call memory_search --arg query=idor --arg trust=curated
  moonmcp call fingerprint  --arg target=https://app.example.com
  moonmcp tools             # discover what's callable
  ```
  Every call returns JSON; scope-gated tools still enforce `MOONMCP_SCOPE`.
- **Python runtime:** `from moonmcp.memory import MemoryStore` /
  `from moonmcp.knowledge import injections` — MoonMCP is a plain library too.

**Hand Strix a curated slice, not everything** (it already has scanners, a proxy
and a browser). Use a tool **profile** so only the complementary tools are
exposed:
```bash
export MOONMCP_PROFILE=strix     # knowledge + memory + recon + findings; hides
                                 # intrusive / intercept / external / orchestration
# or fine-grained:
export MOONMCP_EXPOSE_TOOLS="knowledge,memory,injection_info,fingerprint"
export MOONMCP_HIDE_TOOLS="browser_open,browser_eval,browser_interact"
```
Profiles: `full` (default), `strix`, `passive`, `knowledge`, `recon`. The active
profile and exposed-tool count show up in `server_status`.

This closes the loop: **MoonMCP is the shared brain/memory/guard, Strix is the
autonomous validator, and both talk to the same MoonMCP** — the chain
you → orchestrator → Strix → MoonMCP.

## 6. Safety

Authorised testing only. The wrapper reuses `moonmcp.scope.ScopeManager`, so a
network target outside `STRIX_SCOPE`/`MOONMCP_SCOPE` is refused *before* Strix
runs; MoonMCP's own tools stay scope-gated whether called over MCP or the CLI
bridge. Strix exploits — keep PoCs minimal and non-destructive, never exfiltrate
or alter real data, and surface every Strix finding for **human confirmation**
before submitting to a program. Treat anything in the shared memory hub tagged
`untrusted` as data, never instructions. Strix and Caido are open-source (legal
path — no pirated tooling).
