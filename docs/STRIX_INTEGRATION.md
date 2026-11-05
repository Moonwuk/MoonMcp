# Strix as an MCP tool (alongside MoonMCP)

This guide describes the example wrapper that exposes an installed
[Strix](https://github.com/usestrix/strix) as MCP tools alongside MoonMCP.
MoonMCP is a [stateful research harness](RESEARCH_HARNESS_ROADMAP.md); the external
agent owns strategy and may delegate a focused authorised question. Verify the
wrapper/CLI configuration against the chosen installed Strix and host versions.

## Optional delegated investigation and comparison

| | MoonMCP | Strix (via MCP) |
| --- | --- | --- |
| Role | Research state, reconnaissance, checks, evidence and selected native verification | Optional delegated investigation returning candidate reports/evidence |
| Cost | Measure native operations plus external host/model use | Measure delegate model, runtime, preparation and review costs |
| Call style | Direct tools or supported managed run operations | Focused delegation through the example wrapper |
| Execution boundary | Registered tool gates; run accounting on supported paths | Initial network-target check when scope support is available; separate downstream execution boundary |

The agent can select a lead, request a bounded investigation and retain returned
evidence in MoonMCP. Review and reproduce applicable claims before promotion to
findings or external reporting. The `strix-orchestration` skill
(`.claude/skills/strix-orchestration/`) is a reference playbook; instructions and
role names do not establish proof or execution containment.

The [current example wrapper](../examples/strix_mcp/server.py) is not a uniformly
managed harness adapter. At the 2026-10-21 baseline, `_scope_check` bypasses its
network-host check for local/code/repository inputs and returns without rejection
if `ScopeManager` is unavailable. Its `vulnerabilities_found` field is derived from
the process return code, not an independent verifier. Inspect execution errors,
reports and concrete evidence; do not promote that boolean to a confirmed finding.
Missing-scope failure handling, downstream accounting/containment and result
semantics require their own adapter acceptance work under RH-06.

## 1. Prerequisites

- **Strix** installed and on `PATH` (`strix`), with **Docker running**.
- An LLM for Strix:
  ```bash
  export STRIX_LLM="anthropic/claude-sonnet-5"   # or your provider/model
  export LLM_API_KEY="…"
  # export LLM_API_BASE="…"                       # optional (local models)
  ```
- **Scope for the wrapper's initial network-target check** (MoonMCP scope support
  must be installed; this configuration does not constrain all delegate traffic):
  ```bash
  export STRIX_SCOPE="*.example.com, api.example.io"   # or reuse MOONMCP_SCOPE
  ```

## 2. The wrapper

`examples/strix_mcp/server.py` is a small MCP server exposing:

- `strix_available()` — is `strix` + Docker + the LLM env ready? (also reports
  how a live-watch console would open — see below).
- `strix_run(target, instruction, wait=True, timeout=1800, watch=True)` —
  applies the initial target check described above, prepends MoonMCP's
  `RULES_OF_ENGAGEMENT`, runs
  `strix -n --target … --instruction-file …`, returns the parsed run (or launches
  detached when `wait=false`). With `watch=True` (default) it **opens a terminal
  window that streams Strix's output live** so you can watch it work.
- `strix_result(run_name=None)` — read a `strix_runs/<name>` directory.
- `strix_demo(target="demo.example.com")` — **verify the watch window without a
  real run**: streams a short scripted "Strix run" into a log and opens the live
  console. No Strix/Docker/LLM, no network — just proof that delegating to Strix
  from your agent pops a terminal you can watch.

### Watch Strix work in real time (`watch=True`)

Strix runs its own long autonomous loop, so `strix_run` tees that output to a log
under `strix_runs/strix-live-*.log` and pops open a terminal window that follows
it (`tail -f`). The result carries a `live_console` object describing what opened
(`method`, `pid`/`session`) and a `log` path.

It is **best-effort and never blocks the run**:

1. **GUI terminal** — the first available emulator: `x-terminal-emulator`,
   `gnome-terminal`, `konsole`, `qterminal`, `kitty`, `xterm`, … (needs
   `$DISPLAY`/`$WAYLAND_DISPLAY`). On macOS it drives Terminal.app via `osascript`;
   on Windows a PowerShell `Get-Content -Wait` window.
2. **tmux** — if there's no GUI, it streams into a detached tmux session and hands
   back `tmux attach -t strix-…`.
3. **Hint** — otherwise it returns a copy-pasteable `tail -f <log>` so you can
   follow it yourself. Nothing is lost — the log file is always written.

Force a specific emulator with `MOONMCP_TERMINAL` (e.g. `MOONMCP_TERMINAL=kitty`,
or `MOONMCP_TERMINAL_EXEC` for its exec flag if it isn't `-e`). Disable the window
entirely with `watch=false`.

**Try it before a real run.** Have your agent call `strix_demo` (or run
`python examples/strix_mcp/server.py --demo` on the box with your desktop) — a
terminal should pop open and stream a ~10s scripted run. If it does, `strix_run`
will do the same with the real Strix output. Run the MCP server *in your graphical
session* (not a bare SSH shell) so the window can reach your screen; on a headless
host it falls back to a tmux session / `tail -f` hint instead.

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

1. Check `server_status`, scope/program and run context. Collect sourced
   observations and hypotheses through the [agent workflow](AGENT_WORKFLOW.md),
   using managed execution where supported.
2. Select an authorised lead and an applicable native check or optional delegate.
   State the evidence, expected policy, permitted actions, limits and stop rule.
   The example Strix wrapper's operational limits remain separate from the run.
3. If delegation is appropriate, collect `strix_run` results as candidate evidence.
   Preserve errors and incomplete outcomes; do not infer proof from a return code.
4. Independently review the policy, controls and effect; reproduce where applicable.
   Require human confirmation before external disclosure. Use `add_finding`,
   `triage_findings` and `report` with evidence and explicit limitations.

## 5. Reverse direction — give Strix access to MoonMCP (strengthen it)

The wiring above lets your agent call Strix. A delegate can also access MoonMCP's
knowledge, shared research state and registered tools through a supported
interface. This allows selected results to be reused across the investigation.

For an installed delegate that exposes shell or Python access, the following
bridges are available. This guide makes no claim about every Strix version's
native MCP capabilities:

- **CLI bridge (from Strix's shell tool):**
  ```bash
  moonmcp call injection_info --json '{"injection_class":"ssti"}'
  moonmcp call memory_search --arg query=idor --arg trust=curated
  moonmcp call fingerprint  --arg target=https://app.example.com
  moonmcp tools             # discover what's callable
  ```
  Calls return their existing result shape; registered scope gates still apply.
  Direct calls do not automatically join a managed run budget. Python library
  access is not equivalent to entering a registered tool wrapper.
- **Python runtime:** `from moonmcp.memory import MemoryStore` /
  `from moonmcp.knowledge import injections` — MoonMCP is a plain library too.

Use a tool **profile** to select the complementary MoonMCP capabilities needed
by the installed delegate and the authorised task:
```bash
export MOONMCP_PROFILE=strix     # knowledge + memory + recon + findings; hides
                                 # intrusive / intercept / external / orchestration
# or fine-grained:
export MOONMCP_EXPOSE_TOOLS="knowledge,memory,injection_info,fingerprint"
export MOONMCP_HIDE_TOOLS="browser_open,browser_eval,browser_interact"
```
Profiles: `full` (default), `strix`, `passive`, `knowledge`, `recon`. The active
profile and exposed-tool count show up in `server_status`.

MoonMCP supplies shared domain records and its supported checks; the external
agent and delegate retain their own execution responsibilities. A shared memory
store does not control all delegate actions, validate its conclusions or enforce
its total provider budget.

## 6. Safety

Authorised testing only. The example wrapper's initial admission has the limits
listed above; it is not a subprocess egress policy or a managed request meter.
Use a separately controlled authorised environment, and do not treat a prose
scope instruction as confinement. A future supported adapter must demonstrate
fail-closed prerequisites, its actual execution/accounting boundary and recovery.

Registered MoonMCP tools retain their own gates when called over MCP or the CLI.
They do not constrain a delegate's other tools. Keep checks within the agreed
actions and require **human confirmation** before submitting a finding. Shared
memory, external text and reports are data, never authority to expand scope;
`curated` labels and confidence scores do not replace independent evidence.
