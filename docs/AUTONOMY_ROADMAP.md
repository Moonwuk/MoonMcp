# MoonMCP autonomy roadmap

Current implementation status: [2026-10-21 roadmap reconciliation](ROADMAP_STATUS_2026-10-21.md).
Historical stages below are not a live completion checklist.

MoonMCP's deterministic security engine remains the product core. The autonomy
work adds an optional host/runtime around it rather than replacing specialised,
scope-gated probes with unconstrained LLM shell execution.

Start with the [consolidated implementation priorities](IMPLEMENTATION_PRIORITIES.md)
for the current discovery delivery order: reproduced guard/outcome defects, one
semantic BOLA proof path and faithful preparation using existing components.
The [evidence-driven proposal](VULNERABILITY_DISCOVERY_ROADMAP.md) supplies detailed
requirements; other research plans are conditional, not a mandatory stage sequence.

## Implementation reconciliation (2026-10-15)

Read the [source-based capability audit](CAPABILITY_AUDIT_2026-10-15.md) before
turning historical stages into implementation tasks. Registry extraction,
managed HTTP accounting, leases/recovery, Docker execution, browser actions,
agent scaffolding and other primitives already exist; their coverage and safety
limits differ. The audit identifies the remaining integration and proof work,
not blanket completion of the stages below.

The [faithful research environments roadmap](RESEARCH_ENVIRONMENT_ROADMAP.md)
reuses and hardens those pieces to prepare applications, validate harness fidelity
and preserve portable proofs. It is a parallel practical track, not a requirement
to implement every advanced research proposal first.

## Delivered foundation

The source audit establishes these primitives, not complete coverage or current
runtime certification. Their limits and remaining integration work are recorded
in the audit and the [delivery index](IMPLEMENTATION_PRIORITIES.md).

- Persistent SQLite runs with pause/resume/cancel/fail states.
- Dependency-ordered tasks for coordinator, mapper, hypothesis, validator and
  reporter roles.
- Coverage items and a finish gate.
- Atomic run-budget accounting and actual-send reservation on supported managed
  HTTP paths; direct calls and unsupported transports do not automatically join it.
- Bounded SHA-256-addressed evidence artifacts and an append-only event stream.
- Registered `run_*` MCP tools and the `runs://recent` resource.
- Operator skills for assessment planning, systematic lead validation and run
  coordination.

## Relational discovery after the experimental layer

The [relational discovery roadmap](RELATIONAL_DISCOVERY_ROADMAP.md) proposes
paired-world confidentiality/integrity checks, reviewed executable rules,
information/authority-flow evidence and small-model counterexamples. It starts
with an indirect-disclosure fixture and depends on applicable earlier discovery
gates. It remains deferred until a measured gap justifies the selected paired
experiment; merged documentation neither implements it nor proves system-wide safety.

## Probabilistic discovery after paired executions

The [probabilistic discovery roadmap](PROBABILISTIC_DISCOVERY_ROADMAP.md) extends
the relational proposal with distribution-level checks, cumulative transcripts,
blind observer validation and persistent statistical error control. It starts
with a fixed-horizon synthetic fixture; timing and AI-agent adapters are optional
later work. This is retained research, not the next implementation commitment;
a measured stochastic gap and calibration evidence must justify activation.

## Remaining stages

These headings are retained for reference stability. They describe remaining
deltas, not wholly absent capabilities or the order in which every track must run.
Use the consolidated priorities to select work and the detailed plans for its gates.

### 1. Registry and contracts

Reuse `registry.py`, `toolspec.py` and extracted registration families. Complete
remaining migration and contract gaps against actual registered tools; keep MCP,
CLI, catalog, profiles and documentation consistent. Do not create a second registry
or treat an accounting declaration as evidence of actual metered execution.

### 2. Automatic execution accounting

Preserve existing `run_execute` receipts, actual HTTP-send reservations and
recovery. Extend accounting/cancellation only to explicitly supported adapters
and test their real execution points. Direct typed calls, browser, CLI and raw
transports are not automatically covered. Manual `run_usage` cannot replace an
adapter's enforcement; unmetered managed dispatch must remain blocked.

### 3. Single-agent coordinator

Build the missing task-selection and evidence-validation loop on existing agent
classes, callbacks, run tasks and memory. First integrate one supported lead-to-proof
path; do not infer autonomous reasoning from a role name. Keep policy, budget and
finish decisions deterministic, and do not treat a curated lesson label as an
independent review. Broader planning follows measured misses.

### 4. Sandboxed custom validation

Harden the existing `DockerSandbox` through an opt-in compatible runner, rather
than adding another generic shell tool. Require pinned inputs, supported least
privilege, enforceable egress, bounded processes/output, durable leases and verified
cancellation/cleanup. Command-string URL matching is not a network boundary.
Generated application setup waits for the environment plan's admission gates.

### 5. Browser, proxy and authentication lifecycle

Reuse existing browser action sequences, authentication, repeater/history and
proxy primitives. First repair and test consistent fail-closed routing. Then add
named live sessions, durable dependency-aware recipes and actual-send accounting.
Keep an HTTP-only proof path available. New external proxy integrations require a
concrete need and their own permission/accounting gates.

### 6. Multi-agent scheduling

Reuse existing leases, ownership tokens, heartbeats, hypothesis contradictions
and recovery. Add only missing capability routing, budget subdivision and shared
resource/session locking that the selected work requires. Larger agent fan-out
is deferred; parallelism must not weaken accounting or repeat unknown side effects.

### 7. Product interfaces

Reconcile the existing CLI, viewer/reporting and CI integration before choosing
missing run commands or approval/evidence views. Connect selected interfaces to
existing run state instead of duplicating it. Preserve MCP/library compatibility;
new UI scope must not delay the first end-to-end proof path.

### 8. Evaluation and release gates

Extend existing offline real-tool benchmarks, regression tests and CI with an
independent discovery evaluator. Measure verified causes, false claims, incomplete
checks, requests, replay and total preparation/model cost on vulnerable, patched
and safe cases. Existing test source and green documentation CI are not evidence
of new detector efficacy; record the actual tested revision and limitations.

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

## Beyond the evidence-driven foundation

The [advanced discovery roadmap](ADVANCED_DISCOVERY_ROADMAP.md) proposes the next
research layer: policy consistency across application representations, bounded
state exploration, optional source/trace guidance, root-cause variants and
validated reusable methods. Its entry gates depend on the evidence-driven
discovery foundation; neither proposal marks those capabilities as implemented.
The advanced plan remains a research reference. Activate a selected delta only
when the delivery index's evidence and that plan's applicable entry gates justify it.
