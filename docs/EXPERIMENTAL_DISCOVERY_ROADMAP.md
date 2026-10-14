# Experimental vulnerability discovery roadmap

**Status:** third-stage proposal; documentation only. No runtime capability,
completed prerequisite or measured discovery gain is claimed.
**Planning baseline:** [`27702d3`](https://github.com/Moonwuk/MoonMcp/commit/27702d3037b68dbe31b960ea69fb20ba428469f2), 2026-10-14.
**Predecessors:** [evidence-driven discovery, PR #15](https://github.com/Moonwuk/MoonMcp/pull/15)
and [advanced discovery, PR #16](https://github.com/Moonwuk/MoonMcp/pull/16).
Both were open when this proposal was prepared. Use their pinned
[foundation plan](https://github.com/Moonwuk/MoonMcp/blob/2bfa753eaa87288c71c90fcd16eb2c740170db5e/docs/VULNERABILITY_DISCOVERY_ROADMAP.md)
and [advanced plan](https://github.com/Moonwuk/MoonMcp/blob/da23a953f2cdaaa3481b9b2e183dab109ecff7ca/docs/ADVANCED_DISCOVERY_ROADMAP.md)
for stable references. This document can be reviewed or merged independently;
merging a roadmap does not satisfy an implementation gate.

## Decision and difference from the earlier plans

After the applicable predecessor capabilities work, investigate the conditions
under which a security rule fails, not simply more endpoints or more hypotheses.
The first investment is a small owner-controlled queue/authorisation testbed with
replayable event order. Other engines are conditional investments chosen from
measured misses, not mandatory projects to launch simultaneously.

| Earlier foundation | Additional question in this proposal |
| --- | --- |
| Compose sequences of application actions. | Which interleaving inside those actions exposes a violation? |
| Observe state and runtime paths. | Does the rule survive a declared, controlled fault and recovery? |
| Compare related representations and access paths. | Did one component authorise a different meaning from what the next component executed? |
| Choose useful experiments. | Can a bounded specialist engine reach the state or input that guessing misses? |
| Search variants of one cause. | Are several different capabilities jointly reachable and sufficient for a forbidden effect? |
| Transfer reviewed research methods. | At which discovery stage did a known bug escape, and which change actually fixes that miss? |

The objective is additional independently verified causes at acceptable precision,
cost and replay reliability. A new trace, parser difference, solved constraint,
crash or longer capability chain is not by itself a confirmed vulnerability.

Reuse the [autonomy foundations](AUTONOMY_ROADMAP.md),
[agent workflow](AGENT_WORKFLOW.md) and [outcome contract](TOOL_OUTCOMES.md).
Extend the predecessor's bounded experiment language, receipts and proof records;
do not add a parallel coordinator, verdict protocol or unrestricted shell path.
The designs below are proposals, not descriptions of existing public APIs.

## Entry gates and operating modes

Attach implementation commits and passing tests for applicable gates before
active execution. The names below describe requirements, not new implemented tools.

| Gate | Evidence needed | Predecessor dependency |
| --- | --- | --- |
| G1: trustworthy proof | Declared policy, live isolated identities, typed objects, controls and fresh-state replay; incomplete execution stays explicit. | Foundation M1–M4; advanced A1. |
| G2: admitted execution | Versioned bounded plans, actual-send accounting, scope/credential guards, cancellation, locks and evidence-backed reconciliation. | Foundation transport gates; advanced A3. |
| G3: controlled environment | Approved disposable environment, pinned build/configuration, reset and cleanup, instrumentation provenance and expiring intervention authority. | Advanced A2/A3, plus new harness admission tests. |
| G4: fair measurement | Frozen implemented predecessor, independent evaluator, held-out cases, fixed inputs/budgets and recorded method memory. | Foundation evaluation; advanced A0/evaluation. |
| G5: compositional knowledge | Evidence-backed relations/cause hypotheses; reviewed transfer boundaries when methods cross projects. | Advanced A4; A5 only for cross-project method promotion. |

**External mode** uses explicitly authorised application interactions and the
existing proof boundary. It may investigate observable interpretation differences
and compatible multi-step effects, but cannot assume control of internal queues,
clocks, faults or execution traces. Protocol tests that could affect other users
remain blocked without an isolated target and a specifically approved adapter.

**Cooperative mode** adds an owner-provided isolated test environment and separately
approved source, hooks or local analysis. Authorisation to test an application
is not authorisation to restart services, intercept internal traffic or change
its code. Missing G3 disables those capabilities; it does not disable external
mode or permit a fallback to an unguarded transport.

Fixture design and offline protocol work can start before all gates pass. Active
milestones list their own dependencies. Exclude production chaos testing,
unbounded concurrency, destructive/payment/account-recovery scenarios, automatic
source modification, arbitrary generated code and mandatory multi-agent fan-out.

## Experiment and evidence contract

Add versioned metadata to existing plans/artifacts. Keep proposed experimental
records separate from authoritative operator policy and observed results.

| Record | Minimum additional information |
| --- | --- |
| Environment manifest | Project/fixture identity, build/configuration and adapter versions, reset epoch, topology, approved hooks/faults, data boundaries, lease/expiry and emergency cleanup policy. |
| Schedule/fault recipe | Event identifiers and partial order, barriers, seeded inputs, clock assumptions, permitted interventions, bounds, controls and a replay recipe. |
| Interpretation trace | Input/transformation evidence, component/build, parsed subject/object/action, policy decision, final operation and missing observation points. |
| Directed-search task | Reachability goal, permitted variables/grammar, bounded code region, assumptions, feedback type, engine/version, resource limits and candidate-validation rule. |
| Capability relation | Subject, resource, operation, prerequisites, effect, validity interval, policy/build/reset context and evidence; inferred edges remain labelled. |
| Intervention comparison | Competing cause hypotheses, one declared intervention, matched controls, normal-flow checks, observed effect and remaining confounders. |
| Miss diagnosis | Independently known cause, first evidenced failed stage, possible later failures, diagnostic interventions, uncertainty and remedy evaluation. |

Retain the distinction between the controller's execution outcome, the target's
response to an intentional fault, and the security verdict. A deliberately failed
target dependency can be a successfully observed experiment. A lost controller
receipt or unknown target side effect remains partial/unknown as appropriate;
expected fault injection must never hide a failed controller or swallowed error.

Preserve `_meta["moonmcp.result"]` and managed-receipt precedence exactly as in
[TOOL_OUTCOMES.md](TOOL_OUTCOMES.md). Additive metadata must not silently relabel
historical findings, change existing MCP schemas or replay old actions to backfill
fields. Specify schema migration and adapter capability negotiation in code PRs.

## Design requirements

### 1. Control event order, then introduce bounded faults

Model observable events inside a permitted action, not only completed HTTP calls.
For a queued private-object operation, record the relevant authorisation decision,
permission change and final effect. The owner must specify whether authority is
checked at submission, execution or another boundary, including any permitted
propagation window. A queued action completing after revocation is not inherently
a bug when the declared policy intentionally authorises it at submission.

Use explicit barriers and recorded event order in one supported test stack. A
random seed or fixed sleep alone does not establish deterministic replay. Record
uncontrolled scheduling, clock sources, background jobs and missing events; report
partial control or flakiness rather than promising whole-system determinism.
Systematic interleaving and deterministic simulation are design precedents in
[R1](#design-references) and [R2](#design-references), not drop-in web test harnesses.

Start with event ordering without faults. Then allow a small enumerated set of
owner-approved interventions: delayed delivery, a disposable worker restart,
a dependency being unavailable, or redelivery where the queue contract permits
it. Preserve process and causal constraints; do not create impossible schedules
and present them as naturally reachable. Virtual clocks, when used, are confined
to the fixture; never alter the host clock or unrelated authentication systems.

The controller must have an authenticated, project-bound, expiring lease. Hooks
are disabled by default and must not expose public pause/restart endpoints. Bound
parallel work, pause duration, fault count, observation time, local resources and
cleanup separately. Admission reserves recovery capacity before any intervention.
An independent watchdog follows a pre-approved recovery procedure; it must not
blindly release a paused operation into an unsafe state. If safe recovery cannot
be established, quarantine or discard the disposable fixture and report it.

Minimise event order/fault requirements only on fresh fixtures, retaining the
policy, controls and final effect. Distinguish a verified policy violation under
a declared fault model, evidence of attacker-reachable triggering conditions,
an ordinary reliability defect and an inconclusive result. A simulator-only
violation or test-only intervention does not prove external exploitability.

### 2. Compare meanings across a processing boundary

Start with one controlled component pair and one input family, such as route or
structured-parameter interpretation. Capture what the checking component actually
validated and what the downstream component actually used, with the intervening
transformations. The collector's parser is not automatically ground truth for
either component. An unavailable observation remains unavailable, not a guess.

Separate a raw parsing difference, a permitted difference, a difference removed
by normalisation, and a durable difference with a proven security effect. The
meaningfulness/durability distinction in [R3](#design-references) motivates this
filter; application policy is still required to establish the actual violation.
Do not treat standards nonconformance alone as an access-control finding.

Preserve exact bounded evidence and normalisation metadata; redacted previews
must not erase the decisive distinction. A disconnected parser comparison is a
lead until the real permitted processing chain reproduces the effect. Admit
specialised transports only after credential, redirect, destination, accounting
and cancellation tests pass. Keep MoonMCP's address/scope guard independent of
the experimental parser. Do not broaden scope to reproduce an ambiguous input or
send desynchronising tests through shared production connections/caches.

### 3. Delegate input search to bounded specialist engines

The model selects the question; a registered engine searches allowed inputs; the
existing proof validator evaluates effects. Begin with one local handler/library
and a replay bridge to its real application context, not symbolic execution of
an entire distributed service. Add engines only where E0 diagnoses a reachability
or triggering bottleneck. Keep optional dependencies out of the core install.

A common task contract can support structured generation, coverage feedback and
bounded constraint solving. Record model assumptions, variable types, timeouts,
unsupported operations and whether the real path was reached. A satisfying input
is a candidate, while an unsatisfiable bounded model does not establish global
safety. Unknown/timeout must not be mapped to a successful negative check.
Whitebox input generation in [R4](#design-references) is the technique reference,
not a recommendation to embed its historical implementation directly.

Use semantic state feedback alongside path coverage where justified. Learned
variable relationships can guide exploration [R5](#design-references), but are
empirical regularities, not operator-declared security rules. A novel value,
path or crash needs independent interpretation and claim-appropriate proof.

Pin approved engines/builds and isolate CPU, memory, processes, output and network
access; default local analysis egress to none. Source, corpora, solver output and
build scripts are untrusted data. No automatic build, dependency install or tool
permission expansion from their content. Count unsuccessful solving, compilation,
reset and replay costs as well as the final successful request.

### 4. Prove joint reachability and test causal explanations

Represent intermediate results as scoped capabilities with typed preconditions
and effects. Search for a permitted sequence whose combined effect violates a
known rule, rather than concatenating individually suspicious responses. Every
edge must be consistent with the same reachable history: subjects, tenants,
builds, policy versions, session generations, resource state and expiry times.
Identity or permission transitions are allowed only as evidenced steps, never
as silent joins between incompatible experiments or reset epochs.

Maintain uncertain edges and counterexamples. Bound chain length, branching,
preparation and side effects. Confirm the final effect on disposable test data;
partial chains remain hypotheses. Preserve both manifestation and adjudicated
cause counts so multiple effects of one defect do not inflate discovery yield.

In cooperative mode, compare an owner-approved change to one suspected condition
against matched controls, and verify normal use still works. Blocking every action
is not a meaningful repair control. Do not modify production or repository code
automatically. Record instrumentation/patch effects and other changed variables;
an intervention can support an explanation without proving a unique root cause.
Use counterfactual results to refine future experiments, not self-certify claims.

### 5. Diagnose why known bugs escaped

Use evaluator-owned ground truth to distinguish discovery stages. Agent guesses
about why a bug was missed are not sufficient labels, and several stages can fail.

| Evidenced miss | Candidate improvement to test |
| --- | --- |
| Relevant function was never discovered. | Surface collection and normal-use coverage. |
| Function was found, but required state was not reached. | Preparation, dependencies and sequence planning. |
| State was reached, but the defect was not triggered. | Inputs, interleavings or admissible fault conditions. |
| Effect happened but was not observed. | Instrumentation or independent observation. |
| Observation was misinterpreted or proof was not completed. | Semantic validation, alternatives and evidence collection. |
| A valid proof required excessive work. | Strategy selection and claim-preserving reduction; report this as inefficiency, not a miss. |

Use separate diagnostic runs that may supply one missing step/observation to test
an explanation. Mark them assisted and exclude them from autonomous discovery
scores. If evidence is insufficient, retain an unknown diagnosis. Keep evaluator
labels and assistance out of the agent's memory and future held-out runs.

Create reviewed, isolated fixture mutations paired with patched/safe versions.
Independently establish that each mutation is reachable, changes a security
property and preserves normal use; exclude equivalent, unreachable or merely
broken fixtures with visible reasons before freezing evaluation denominators.
[R6](#design-references) motivates mutation-based assessment, not a claim that
synthetic success predicts real-target effectiveness. Mix synthetic cases with
curated historical cases and unfamiliar implementations, respecting data rights.

Select strategies first with transparent, versioned rules based on validated
misses and observed cost. Freeze selection policies for evaluation, compare with
fixed/simple baselines, log selection propensities if later doing offline policy
evaluation, and test negative transfer. No automatic model training on self-issued
verdicts or unrestricted publication of generated vulnerable applications.

## Delivery plan

All **28 tasks across seven milestones** are proposed and unchecked. Priorities
are dependency/decision order, not dates. Touchpoints identify integration seams;
recheck the implementation at that time before choosing new module/API names.

### E0 — Establish the experiment contract and miss baseline (P0)

**Depends on:** G4 for comparative claims; offline fixture work may start earlier.
**Touchpoints:** `moonmcp/bench.py`, existing evaluator/fixtures, run artifacts.

- [ ] ED-01: Pin the implemented advanced baseline and applicable G1–G5 evidence;
  freeze inputs, method memory, budgets, permitted capabilities and comparison modes.
- [ ] ED-02: Define versioned environment/experiment records, intervention approval,
  controller authentication, lease expiry, watchdog and recovery contracts.
- [ ] ED-03: Build a queue/permission fixture with vulnerable, patched and legitimate
  submission-authorised variants; separate agent views from evaluator ground truth.
- [ ] ED-04: Record baseline misses by evidenced stage, with unknown/assisted labels,
  normal-flow controls and predeclared precision, replay and resource thresholds.

**Acceptance:** the fixture resets independently; policy is explicit; labels and
the failing order are hidden from the agent. Baseline failures remain visible.
No intervention becomes available merely by parsing a proposed environment record.

### E1 — Discover and replay significant event orders (P0)

**Depends on:** E0 and G1–G4. **Touchpoints:** existing bounded plans,
`moonmcp/execution.py`, `moonmcp/runs.py`, `moonmcp/web/workflow.py`, lab adapter.

- [ ] ED-05: Add authenticated, disabled-by-default hooks for one supported stack,
  bounded barriers, event correlation and an explicit uncontrolled-event inventory.
- [ ] ED-06: Explore feasible event orders without faults and retain causal/process
  constraints, identity/policy snapshots and final-state observations.
- [ ] ED-07: Replay and reduce the order on fresh fixtures while retaining controls;
  report failed replays, nondeterminism and total experimentation cost.
- [ ] ED-08: Test lease expiry, absent hooks, clock uncertainty, lost receipts and
  cancellation; ensure watchdog/quarantine policy prevents orphaned interventions.

**Acceptance:** discover the unsupplied violating order in the vulnerable fixture,
reject patched and legitimately submission-authorised cases, and meet the frozen
replay threshold. A fixed sleep, missing event or deadlocked fixture is not proof.

### E2 — Test security properties under declared faults (P1)

**Depends on:** E1 and renewed G3 approval for each fault. **Touchpoints:** lab
adapter, outcome/proof adapters, run recovery and fixture lifecycle.

- [ ] ED-09: Implement enumerated delay/restart/dependency/redelivery controls only
  where the selected test environment's contracts allow them.
- [ ] ED-10: Combine one fault with a bounded schedule; record the causal constraints,
  recovery observation, expected target failure and actual controller outcome.
- [ ] ED-11: Separate reliability defects, security violations under fault assumptions
  and demonstrated attacker reachability; include no-fault and allowed-policy controls.
- [ ] ED-12: Exercise exhausted budgets, broken cleanup, ambiguous mutation and lease
  loss; test quarantine/disposal without silently repeating a state-changing action.

**Acceptance:** reproduce a seeded fault-dependent policy violation and its repaired
control, preserve actual outcome uncertainty, and leave no active intervention
outside its lease. Report simulator-only effects without claiming external reachability.

### E3 — Validate interpretation-boundary discrepancies (P1, parallel option)

**Depends on:** E0, G1/G2/G4 and G3 for internal observation. E1/E2 are not required.
**Touchpoints:** transport/tool registry, `moonmcp/execution.py`, bounded evidence,
predecessor property validators and a controlled two-component fixture.

- [ ] ED-13: Define one input family's interpretation/transformation record and
  capture the actual checked meaning, downstream meaning and final operation.
- [ ] ED-14: Add paired cases for meaningful, allowed, normalised-away and unobserved
  differences; keep collector assumptions and truncation visible.
- [ ] ED-15: Connect a surviving discrepancy to an explicit policy and test-object
  effect through the real approved chain, with an independent control.
- [ ] ED-16: Verify adapter accounting, credential isolation, cancellation and scope
  guards independently of tested parsers; reject unsafe shared-connection targets.

**Acceptance:** the security-relevant fixture yields a replayable proof while benign
or erased differences do not. A parser disagreement alone cannot satisfy a finding.
External mode reports unavailable internal observations rather than inventing them.

### E4 — Add a directed local input-search adapter (P1, conditional)

**Depends on:** E0, G1–G4 and implemented advanced A2/A3; invest only when miss
analysis supports it. **Touchpoints:** bounded plan/adapter registry, source/runtime
feedback, isolated analysis runner and real-context replay.

- [ ] ED-17: Define the engine-neutral task contract and implement one bounded local
  handler/grammar adapter with pinned versions and no default network egress.
- [ ] ED-18: Compare structured/coverage-guided search and, where supported, bounded
  solving against a simple baseline under the same assumptions and resources.
- [ ] ED-19: Add optional semantic feedback without treating learned invariants as
  policy; replay generated candidates in the actual permitted application context.
- [ ] ED-20: Test timeout/unknown/unsatisfiable-model handling, unsupported semantics,
  hostile artifacts, failed builds and complete accounting of analysis overhead.

**Acceptance:** reach and verify a fixture case missed by the matched simple search,
or report no demonstrated gain. Candidate/coverage success is separate from proof;
local-only behaviour cannot establish real-context exploitability.

### E5 — Validate composite effects and causal interventions (P2)

**Depends on:** E0, G1/G2/G4/G5 and predecessor advanced A3/A4; G3 for interventions.
Consume E1–E4 outputs only when a scenario actually needs them.
**Touchpoints:** flags/cause relations, experiment type checks, workflow proofs.

- [ ] ED-21: Add capability preconditions, typed effects and validity intervals;
  detect incompatible subjects, builds, sessions, resource states and reset epochs.
- [ ] ED-22: Plan bounded jointly reachable scenarios and independently observe the
  final forbidden effect, retaining unproven edges and safe combinations.
- [ ] ED-23: Support owner-approved single-condition comparisons with matched normal
  flows and confounder records; do not apply source changes automatically.
- [ ] ED-24: Test impossible joins, expired intermediate capabilities, partial chains,
  over-broad repair controls and adjudicated cause/manifestation grouping.

**Acceptance:** reproduce a composed violation in one consistent history; reject a
lookalike assembled from incompatible evidence. An intervention supports only the
causal claim warranted by its controls, not a declaration of unique root cause.

### E6 — Improve selection from independently diagnosed misses (P2)

**Depends on:** E0 plus a validated engine from E1/E3/E4 and G4; predecessor A5 only
for transferring methods. **Touchpoints:** evaluator, fixture curation, coordinator
selection and project-scoped reviewed method records.

- [ ] ED-25: Curate independently checked mutations, historical examples and safe
  counterexamples; freeze application/mechanism splits and exclusion reasons.
- [ ] ED-26: Run assisted diagnostic interventions separately from discovery trials;
  validate miss labels, observation gaps and unknown/multiple-cause diagnoses.
- [ ] ED-27: Evaluate a transparent versioned selector against fixed/simple policies,
  using matched budgets, frozen memory and safeguards against evaluation leakage.
- [ ] ED-28: Publish gains, losses, costs and safety results per engine/environment;
  promote or roll back selectors/methods only after held-out acceptance review.

**Acceptance:** the selected remedy improves the independently labelled failure
stage and useful discovery on held-out cases, rather than only synthetic training
scores. No-gain and negative-transfer results remain visible and block overclaims.

## Evaluation and release gates

The primary comparator is the **implemented advanced system**, not these documents
or a weaker probe-only baseline. Keep a native predecessor run, a minimally
adapted predecessor with the same approved controls/observations, and the proposed
strategy. Record adaptation changes. Separate extra-environment capability gains
from strategy gains; a predecessor without queue control is not an equal-capability
control for the new scheduler. Compare external and cooperative tracks separately.

Freeze scenario/build/configuration, policy, identities, seeds, reset procedure,
model/provider, prompts, sampling, methods and cost ceilings. Use at least five
independently reset paired trials per agent configuration as an initial protocol,
not a statistical guarantee; predeclare sample-size needs and acceptance margins
before examining held-out results. Record execution histories as well as seeds.

Keep evaluator labels, fixture switches and causal answers inaccessible through
source, traces, hook names, files or agent memory. Normal application semantics
and approved control locations may be visible; a test-only identifier naming the
flaw is answer leakage. Split by applications and mechanisms, keep synthetic and
historical results distinct, and exclude assisted runs from autonomous scores.

| Measure | Required reporting |
| --- | --- |
| Incremental verified causes | New causes versus the matched predecessor, causes lost, uncertain grouping and manifestation counts. |
| Precision and recall | Independent true/false claim counts; known-ground-truth recall with blocked/unfinished eligible cases retained. Real unknown targets have observed yield, not complete recall. |
| Replay and reachability | Fresh-fixture replay rate, failed/flaky runs, schedule-control limits, simulator-only results and evidence for externally reachable conditions. |
| Cost | Actual sends, tool/model usage, local CPU/memory/time, build/reset/control/solver/reduction overhead and zero-finding runs; unavailable usage is not zero. |
| Diagnosis and selection | Accuracy/unknown rate of independently labelled miss stages, assisted-run accounting, per-engine ablations and negative transfer. |
| Safety and compatibility | Scope/credential boundaries, lease/cleanup failures, unapproved effects, budget overruns, unknown operations replayed, data leakage and readable legacy receipts. |

An observed violation is subject to its declared policy and environment assumptions.
Do not inflate severity from a fault the assumed attacker cannot induce, count
random crashes as access-control findings, or silently remove infeasible/missed
cases after evaluation. Report bounded search coverage, not exhaustive safety.

**Deterministic gate:** all required positive, patched, legitimate-exception,
missing-evidence and guard/recovery fixtures pass. Proof must survive fresh-state
replay; unsupported control/transport capabilities fail closed. These are guarantees
about the declared suite, not every possible target or interleaving.

**Agent gate:** meet predeclared precision/recall/replay margins and total resource
ceilings in repeated held-out trials. Review unexplained causal claims and failed
runs; publish per-mode ablations and no-gain results. More hypotheses, mutations,
threads or solver calls cannot substitute for verified discovery. Roll back a
selector/adapter when it fails its gate rather than silently increasing the budget.

## First implementation PR

Start with ED-01–ED-04: an independently resettable private-object queue fixture,
two test subjects, explicit authority timing and a frozen predecessor comparison.
Include a vulnerable case, its repair, a permitted submission-time policy and an
incomplete observation case. Keep answer labels and failing event order private
to the evaluator. Define the environment lease and cleanup tests before hooks.

Then implement E1 for that single stack: admitted hooks, schedule recording,
independent effect observation and fresh-state replay. Expand to E2 only after
ordering alone is reliable. Choose E3 or E4 from measured bottlenecks instead of
funding every engine by default. Composite/diagnostic work reuses validated pieces.

Implementation PRs must list satisfied gates, schema/migration impact, explicit
owner permissions, test results and actual measurement. This proposal changes
only Markdown documentation: no runtime code, dependencies, configuration, tests,
service interventions or benchmark results are delivered.

## Design references

Primary references checked on 2026-10-14. They motivate techniques and limits,
not claims of MoonMCP effectiveness. Recheck versions, APIs and licensing before
adopting any implementation; none becomes a dependency through this document.

- **R1 — [CHESS: A systematic testing tool for concurrent software](https://www.microsoft.com/en-us/research/publication/chess-a-systematic-testing-tool-for-concurrent-software/).**
  Systematic interleaving exploration and reproducible failing executions motivate
  controlled ordering rather than load-based timing guesses.
- **R2 — [FoundationDB: Simulation and Testing](https://apple.github.io/foundationdb/testing.html).**
  Describes tightly integrated deterministic simulation and component failures.
  Arbitrary owner applications require their own declared harness and fidelity limits.
- **R3 — [The HTTP Garden](https://arxiv.org/html/2405.17737v1).**
  Distinguishes meaningful and durable parsing discrepancies while observing origin
  interpretations and intermediary transformations. A discrepancy still needs impact.
- **R4 — [Automated Whitebox Fuzz Testing](https://www.microsoft.com/en-us/research/publication/automated-whitebox-fuzz-testing/).**
  Explores trace-derived constraints and generated inputs in SAGE. This motivates
  a bounded search adapter, not whole-service symbolic execution or a safety proof.
- **R5 — [The Use of Likely Invariants as Feedback for Fuzzers](https://www.usenix.org/conference/usenixsecurity21/presentation/fioraldi).**
  INVSCOV augments coverage with observed variable relationships; empirical novelty
  must remain distinct from an authoritative security property.
- **R6 — [Systematic Assessment of Fuzzers using Mutation Analysis](https://www.usenix.org/conference/usenixsecurity23/presentation/gorz).**
  Motivates independent mutation-based evaluation and separating triggering from
  detection. Synthetic-case gains require separate real-mechanism validation.
