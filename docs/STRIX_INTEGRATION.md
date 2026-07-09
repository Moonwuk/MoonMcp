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

## 5. Safety

Authorised testing only. The wrapper reuses `moonmcp.scope.ScopeManager`, so a
network target outside `STRIX_SCOPE`/`MOONMCP_SCOPE` is refused *before* Strix
runs. Strix exploits — keep PoCs minimal and non-destructive, never exfiltrate or
alter real data, and surface every Strix finding for **human confirmation** before
submitting to a program. Strix and Caido are open-source (legal path — no pirated
tooling).
