# MoonMCP autonomy roadmap

MoonMCP's deterministic security engine remains the product core. The autonomy
work adds an optional host/runtime around it rather than replacing specialised,
scope-gated probes with unconstrained LLM shell execution.

## Delivered foundation

- Persistent SQLite runs with pause/resume/cancel/fail states.
- Dependency-ordered tasks for coordinator, mapper, hypothesis, validator and
  reporter roles.
- Coverage items and a finish gate.
- Atomic request/tool/intrusive-call budget accounting.
- Bounded SHA-256-addressed evidence artifacts and an append-only event stream.
- Twelve `run_*` MCP tools and the `runs://recent` resource.
- Operator skills for assessment planning, systematic lead validation and run
  coordination.

## Remaining stages

### 1. Registry and contracts

Split registration out of `server.py`; define typed `ToolSpec`, input/output,
risk, scope and evidence contracts. Generate MCP exposure, CLI help, catalog,
profiles and documentation from that registry.

### 2. Automatic execution accounting

Associate tool calls with an active run, reserve budget before execution, record
actual requests and artifacts after execution, and make cancellation propagate
to HTTP requests and external processes. Manual `run_usage` remains useful for
external workers but must not be the only enforcement path.

### 3. Single-agent coordinator

Add a provider-neutral agent loop that recalls memory, selects the next task,
loads only relevant tool families, updates coverage, validates leads and stops
on policy, budget or convergence. Keep policy and finish decisions deterministic.

### 4. Sandboxed custom validation

Add an optional rootless container backend with CPU, memory, process, time and
output limits. Derive network egress from MoonMCP scope, block metadata/private
ranges by default, audit commands, and require approval for state-changing work.

### 5. Browser, proxy and authentication lifecycle

Persist browser contexts and role-specific sessions; correlate browser actions
with HTTP exchanges; add adapter interfaces for Caido, mitmproxy, ZAP and licensed
Burp. Reuse captured requests for IDOR, workflow and business-logic validation.

### 6. Multi-agent scheduling

Add task leases, heartbeats, worker capabilities, child budgets, contradiction
resolution and target/session locks. Parallelise independent passive/host work;
serialize flows that share authentication or mutate target state.

### 7. Product interfaces

Add `moonmcp run start/status/watch/resume/stop/report`, a local authenticated
viewer/TUI, approval queue, task graph, coverage matrix, evidence explorer and CI
exit policies. Preserve MCP and library interfaces as first-class options.

### 8. Evaluation and release gates

Measure precision/recall, requests, duration and cost on vulnerable, patched and
noisy fixtures. Add agent-level benchmark runs, scope-violation invariants,
resume/cancellation tests and reproducible versioned results.

For a later research layer, see the
[experimental discovery roadmap](EXPERIMENTAL_DISCOVERY_ROADMAP.md): controlled
event order and faults, interpretation boundaries, guided input search,
compositional proofs and diagnosis of missed vulnerabilities. Its implementation
gates depend on the earlier discovery proposals; this link marks no work done.

## Skill-methodology assessment

The [obra/superpowers](https://github.com/obra/superpowers) methodology is useful
where it adds decision discipline rather than duplicating generic development
instructions:

- brainstorming + writing plans → `assessment-planning`;
- systematic debugging + TDD + verification → `systematic-validation`;
- executing plans + parallel dispatch + branch finishing → `run-coordination`.

Generic Git worktree, code-review and software-branch skills are intentionally
not copied into the MoonMCP operator pack: they improve development of MoonMCP,
not operation of a security assessment, and are better installed directly from
Superpowers in a coding harness.
