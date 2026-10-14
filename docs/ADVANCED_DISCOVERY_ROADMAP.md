# Advanced vulnerability discovery roadmap

**Status:** next-stage proposal; documentation only. No capabilities or measured
improvements are delivered by this document.
**Planning baseline:** [`27702d3`](https://github.com/Moonwuk/MoonMcp/commit/27702d3037b68dbe31b960ea69fb20ba428469f2), 2026-10-14.
**Predecessor:** [evidence-driven discovery proposal, PR #15](https://github.com/Moonwuk/MoonMcp/pull/15),
with a [pinned roadmap](https://github.com/Moonwuk/MoonMcp/blob/2bfa753eaa87288c71c90fcd16eb2c740170db5e/docs/VULNERABILITY_DISCOVERY_ROADMAP.md).
That PR was open when this proposal was prepared. References are pinned so this
plan can be reviewed or merged independently; merging either document does not
satisfy an implementation gate.

## Decision: improve the experiments, not the tool count

After the predecessor's foundation is implemented and validated, make MoonMCP
better at discovering **which security assumptions to test**. Prioritise
inconsistent enforcement across related application paths, combinations of
states and actions, and optional source/runtime feedback.

> Model related actions and data → establish the applicable rule → propose a
> discriminating experiment → execute within policy → verify and minimise the
> proof → search for related causes → retain a validated research method.

The outcome to measure is additional independently verified vulnerability causes
on unfamiliar applications at an acceptable false-positive rate and cost. More
URLs, hypotheses, response differences or cooperating agents are not that outcome.
All expected benefits below are hypotheses to evaluate, not efficacy claims.

This is the next research layer, not a replacement for the
[autonomy roadmap](AUTONOMY_ROADMAP.md), [agent workflow](AGENT_WORKFLOW.md) or
[execution outcome contract](TOOL_OUTCOMES.md). Reuse their run lifecycle,
flags/hypotheses, proof storage and executor. Do not create a second scheduler,
findings database or verdict protocol.

## Entry gates and scope

Before enabling active work in this plan, attach implementation and test evidence
for the applicable predecessor gates. Existing roadmap checkboxes are not proof.

| Gate | Required foundation | Predecessor milestones |
| --- | --- | --- |
| F1 | Verified-claim contract, policy provenance, controls, redacted proof and fresh-fixture replay; execution status remains separate. | M1–M2 |
| F2 | Isolated live identities, typed objects, observed ownership and dependency-aware request recipes. | M2–M3 |
| F3 | Scope and credential-destination checks, actual-send budgets, cancellation, approval and evidence-backed recovery for every selected transport. | M2–M4 |
| F4 | Resettable application state, permitted mutations, cleanup capacity, resource/session locks and explicit consistency windows. | M4 |
| F5 | An independent evaluator, frozen baseline agent and matched-budget repeated trials, including safe and patched cases. | M0 and M5 |

A0 fixture/protocol work may begin before these gates pass, but must not enable
unapproved target execution. Read-only A1 experiments require F1–F3 and F5;
state-changing or replay-minimisation work additionally requires F4.

Keep two independent assessment modes. **External mode** uses authorised traffic,
accounts, declared policy and observable state. **Cooperative mode** adds explicitly
provided source/build identity and optional instrumentation in the owner's test
environment. Missing source or telemetry is a supported limitation, not a reason
to stop external mode or weaken its proof requirements.

Initially exclude unrestricted shell/code generation, production concurrency
stress, destructive/account-recovery/payment experiments, unapproved targets and
a mandatory multi-agent architecture. Prefer one coordinator and bounded test
primitives. Any later parallelism needs its own effectiveness and safety evidence.

## Design

### 1. Model security relationships across representations

Extend the foundation's resource model with relationships between protected data,
representations, operations and execution paths. Candidate relation types include
`derived_from`, `contains`, `version_of`, `served_by` and `processed_by_job`.
Access inheritance is a separate policy assertion, not an automatic consequence
of a content relationship.

For example, a private document may appear in direct reads, search results,
attachments and exports. Establish which representations actually contain its
protected information and which policy applies to each. A shared identifier or
similar name alone does not establish equivalence.

Every relation needs evidence references, project/tenant boundaries, subject and
build context, freshness and a state such as observed, declared, inferred,
contradicted or stale. Keep competing interpretations and invalidate dependent
plans when material evidence changes. Start with bounded indexed records in the
existing project store; a separate graph database is not a prerequisite.

| Relation established by evidence | Candidate property to investigate | Important safe alternative |
| --- | --- | --- |
| Direct and derived views contain the same protected fields. | Each view enforces its applicable access policy. | An approved export is an independent copy with different retention/access rules. |
| Single and batch operations act on the same resource type. | Batch processing respects the declared per-object authorisation rule. | Batch and single operations legitimately have different privileges. |
| Ownership or tenant membership changes. | Dependent access reflects the declared new policy and propagation window. | Historical snapshots intentionally preserve earlier membership or content. |
| Immediate and queued paths perform a related operation. | Each evaluates authority at the policy-defined point in time. | The policy intentionally authorises at submission rather than execution. |

Compile properties into paired/control experiments, not a universal expectation
that two responses must match. Record the fields, relationship and state that
matter. Reject a proof when a required policy is unknown, contradictory or merely
inferred by the model. Preserve the observation and the missing policy question.
The stateful property-checker approach in [R1](#design-references) is a design
reference, not a ready-made oracle for an arbitrary application's business rules.

### 2. Connect behaviour to code and observed execution, optionally

Define a provider-neutral adapter for route/handler mappings, relevant data-flow
or policy-check locations, and runtime observations linked to request receipts.
Bind each result to the actual deployment/build and analysis version. A stale or
unmatched source index is a lead, not an explanation of current execution.

Start with one language/framework and one owner-controlled fixture. Source
analysis can propose where related operations use different checks; traces can
show whether the experiment reached the intended path. Neither missing text in a
handler nor a missing span proves that an authorisation check is absent: it may
be in middleware, a datastore, another service, or unobserved instrumentation.

Report unavailable, sampled, dropped and uncorrelated telemetry explicitly. Use
separate instrumentation for security decisions when the owner provides it, and
never interpret normal trace success as a security verdict. Compare with an
uninstrumented fixture to detect instrumentation-induced behaviour changes.
CodeQL's analysis/variant concepts [R2](#design-references) and OpenTelemetry's
traces [R3](#design-references) are optional adapter candidates, not new mandatory
runtime dependencies or promises of complete coverage.

Source imports are read-only by default. Repository content, comments, build
scripts, analysis plugins and telemetry are untrusted inputs. Do not run a build
or fetch dependencies merely because a repository requests it. Any approved
analysis build needs its own isolated environment, pinned inputs, resource limits
and egress policy. Keep secrets and private source out of model-facing exports
unless specifically authorised; check adapter licensing before adoption.

### 3. Explore states with a bounded experiment language

The foundation replays known actions. This layer composes new sequences from
known actions, their preconditions, typed outputs and observable effects. Use a
partial state model with explicit unknowns, not an assumed complete application
model. Distinguish a real new state from timestamps, nonces or cosmetic response
changes. A normalisation rule must not discard owner, tenant or protected fields.

An experiment is a versioned declarative record. It may invoke only registered,
policy-checked primitives: prepare a permitted fixture object, send a scoped
recipe, extract a typed value, select an approved identity, observe a state,
assert a registered property and clean up. It is not Python, shell or a route to
arbitrary tool invocation.

| Proposed record | Required information beyond foundation references |
| --- | --- |
| Security relation | Typed endpoints, semantics, evidence/policy provenance, contradiction and invalidation rules. |
| Property specification | Protected information/action, applicable subjects/states, policy source, safe exceptions, control and observation rules. |
| Experiment specification | Schema version, property and recipe references, typed bindings, preconditions, bounded control flow, requested capabilities, resource limits and cleanup plan. |
| Execution observation | Receipt, build/session generation, state/path projection, instrumentation coverage and missing-data limits. |
| Cause hypothesis | Verified finding references, proposed failed assumption/trust boundary, supporting and disconfirming evidence, confidence and variant constraints. |
| Research method | Preconditions, approved property/test template, proof requirements, safe counterexamples, independent evaluation and provenance. |

These names are design proposals, not existing public APIs. The model proposes a
plan; deterministic checks admit it; the existing executor applies runtime guards;
the proof validator assesses its observations. Reject unresolved references,
unknown primitives, forbidden capabilities and unbounded loops before execution.
Static admission cannot replace runtime checks on extracted URLs and data.

Limit steps, branching, polling, elapsed time, tool calls, HTTP sends, local
analysis resources and model usage separately. All baselines, controls, resets,
retries, shrinking and cleanup consume their applicable budgets. Reserve cleanup
capacity before mutation; an idempotency key or an HTTP method alone is not proof
that repeating an action is safe.

Explore only feasible transitions and score progress by declared property/state
coverage and newly observed paths when available. Save the chosen experiment and
an evidence-based rationale. Negative results remain scoped to their tested
subject/object/operation/state and become stale when relevant conditions change.
Hypothesis's state-machine primitives [R4](#design-references) are a possible
implementation building block, not an out-of-the-box live-target executor.

After a verified violation, remove unnecessary steps or values on fresh isolated
fixtures while preserving the same claim, valid preconditions, controls and
observable effect. Never minimise by removing the control that makes the claim
credible. Record every attempt and cost; stop with the smallest reproduction found
within the budget, without claiming a globally minimal sequence. Preserve flaky
or timing-dependent results as such. Do not silently rerun an ambiguous mutation.
Controlled ordering/concurrency research remains a later, separately approved
extension rather than part of the first sequence engine.

### 4. Search variants and re-evaluate changes by cause

Turn a confirmed finding into a **cause hypothesis**, not an automatic conclusion
about internal implementation. Separate the observed policy violation from the
proposed explanation. Trace which trust boundary, lifetime assumption, shared
component or missing condition could account for it; retain alternatives.

Use that hypothesis to rank related operations in the authorised application.
Cooperative mode may inspect shared helpers or analogous code paths; external
mode may compare evidenced behavioural mechanisms, with lower attribution
certainty. Every candidate needs its own applicability checks, control and proof.
A related name or shared function is not itself another confirmed vulnerability.
CodeQL documents this seed-to-variant approach [R2](#design-references).

For an approved code or behaviour change, map impacted relations/properties and
select tests worth re-running. Bind the comparison to known before/after builds,
policy versions and feature/configuration context. An untrusted diff must not
trigger target execution or expand scope. Missing dependency links require
explicit coverage limits and periodic broader checks, not a claim that omitted
areas are safe. Compare change-guided selection with full-suite and budget-matched
baseline selection on held-out regressions.

Group verified manifestations by independently adjudicated cause where evidence
supports it. Keep occurrence details and uncertain groupings visible. Do not
claim ten independent bugs because one faulty shared component affects ten URLs,
or merge unrelated bugs solely because their responses look similar.

### 5. Retain validated methods, not self-certified lessons

A reusable method should state: mechanism indicators, applicability conditions,
policy questions, bounded experiment template, required proof, known safe
lookalikes and failure modes. Store independently confirmed successes and useful
refutations with versioned provenance. Retrieval suggests an experiment; it does
not establish that a rule or permission carries over to a new target.

Keep target-specific credentials, raw private data, scope grants and proprietary
code out of transferable methods. Default to project isolation; cross-project
promotion requires explicit approval and sanitisation. Quarantine new methods,
review them independently, test their safe counterexamples, and support expiry,
rollback and revocation. An agent's own confident verdict is not training ground
truth. Automatic self-training and unreviewed method publication are non-goals.

Measure transfer on unfamiliar applications and different implementations of the
mechanism. Separate recall of a known scenario, adaptation to a new implementation
and discovery in a previously unseen combination of features. Record memory
versions, reset histories and test splits so hidden-case knowledge cannot leak
through a prior run or a newly published method.

## Delivery plan

All 24 tasks are proposed and unchecked. Priorities are delivery order, not dates.
Touchpoints identify integration seams; new module names and schemas must be
settled in implementation review after rechecking the then-current code.

### A0 — Freeze the question and establish a challenge fixture (P0)

**Depends on:** no new runtime capability; F5 before comparative claims.
**Touchpoints:** existing benchmark harness, `moonmcp/bench.py`, isolated fixtures
and evaluator code under `tests/`.

- [ ] AD-01: Record foundation gate evidence and pin the implemented predecessor
  baseline, model, prompts, inputs, budgets and evaluation protocol.
- [ ] AD-02: Build an owner-controlled application with related document views
  and a queued action; provide vulnerable, patched and legitimate-exception modes.
- [ ] AD-03: Separate fixture reset/ground truth from agent access; define hidden
  variants and root-cause adjudication before testing candidate changes.
- [ ] AD-04: Add policy-unknown, session-stale, interrupted and evidence-missing
  cases; record baseline discoveries, false claims, misses and costs.

**Acceptance:** independently reset runs reproduce ground truth. The agent knows
normal use and intended rules, but not a failing route, triggering sequence,
fixture switch or expected answer. Baseline failures are published, not removed.

### A1 — Find inconsistent enforcement across related paths (P0)

**Depends on:** A0 and F1–F3/F5; F4 for any mutation.
**Touchpoints:** existing project resource/memory records, `moonmcp/flags.py`,
`moonmcp/leadpipe.py`, `moonmcp/web/authz.py` and proof adapters.

- [ ] AD-05: Add versioned, bounded security relations with provenance, conflicting
  evidence, freshness and project isolation; reuse existing persistence.
- [ ] AD-06: Define property specifications and explicit safe exceptions; prevent
  an inferred rule from silently becoming an authoritative policy.
- [ ] AD-07: Generate paired/control plans for direct versus derived access and
  single versus batch operations where declared policies make them applicable.
- [ ] AD-08: Rank evidence gaps and execute through the existing metered path;
  connect resulting receipts and counterevidence to the original hypothesis.

**Acceptance:** find the fixture's policy inconsistency without a hard-coded bad
route, and reject its patched and legitimate-exception variants. Unknown policy
remains inconclusive. Relation staleness invalidates dependent claims/plans as
specified; additional signals alone do not satisfy the discovery gate.

### A2 — Add optional source and runtime guidance (P1, parallel track)

**Depends on:** A1 records, approved cooperative environment and applicable gates.
**Touchpoints:** tool/adapter registry, `moonmcp/execution.py`, receipt artifacts
and the A1 relationship model. A2 is not a dependency of external-mode A3.

- [ ] AD-09: Define a build-bound source/observation adapter with availability,
  provenance, resource accounting and unsupported-language handling.
- [ ] AD-10: Implement one framework's route/check mapping and correlated runtime
  feedback, including explicit security-decision instrumentation where approved.
- [ ] AD-11: Test stale builds, missing middleware visibility, trace sampling,
  hostile source content, secret redaction and instrumented/uninstrumented parity.
- [ ] AD-12: Compare guided and unguided runs with identical access to source and
  telemetry, then report the extra-information benefit separately.

**Acceptance:** observations establish which path was actually seen, not which
path the model expected. Static and trace signals remain leads until independently
verified. External mode still works with the adapter absent or disabled.

### A3 — Compose experiments and minimise reproducible proofs (P1)

**Depends on:** A1 and F1–F5; optionally consumes A2 observations.
**Touchpoints:** `moonmcp/leadpipe.py`, `moonmcp/web/workflow.py`,
`moonmcp/execution.py`, `moonmcp/runs.py` and the fixture reset harness.

- [ ] AD-13: Specify the restricted experiment language, type/capability checks,
  bounded control flow and mapping to existing tool schemas and receipts.
- [ ] AD-14: Explore precondition-valid action sequences with explicit unknown
  states, semantic progress scoring and narrow contextual negatives.
- [ ] AD-15: Minimise a verified sequence on fresh fixtures without dropping
  material controls; preserve attempts, limitations and total replay cost.
- [ ] AD-16: Test cancellation, policy changes, malicious bindings, budget stops,
  cleanup failure and interrupted mutations without implicit replay.

**Acceptance:** compose a previously unsupplied sequence that reaches a verified
violation, reproduce it on a fresh fixture, and obtain no verified finding on the
patched case. Forbidden/unbounded plans are rejected before a send. Reduction
preserves the claim; unresolved state never becomes a clean negative.

### A4 — Find variants and prioritise changed behaviour (P2)

**Depends on:** A1 and A3; code-based variants additionally require A2.
**Touchpoints:** findings/flags, project relations, source adapter when enabled,
coverage selection and independently labelled regression fixtures.

- [ ] AD-17: Store cause hypotheses separately from verified effects, including
  alternatives and evidence needed to strengthen causal attribution.
- [ ] AD-18: Generate candidates from shared evidenced mechanisms and validate
  each independently; retain safe related paths as counterexamples.
- [ ] AD-19: Map approved build/behaviour changes to impacted properties; maintain
  an explicit fallback/broader-check policy for incomplete dependency maps.
- [ ] AD-20: Evaluate cause grouping and change-guided selection on held-out
  regressions, including unrelated changes and intended policy changes.

**Acceptance:** a confirmed seed leads to an independently verified variant while
safe lookalikes are rejected. Related occurrences are not inflated into separate
causes without justification. Report missed regressions and selection overhead;
an empty selected-test set is not a declaration that the change is safe.

### A5 — Transfer reviewed research methods and measure generalisation (P2)

**Depends on:** A4 and independently adjudicated source cases.
**Touchpoints:** project-scoped memory/method storage, coordinator retrieval,
redaction/export controls and the held-out evaluation harness.

- [ ] AD-21: Define versioned method records with applicability, proof rules,
  safe counterexamples, provenance and independent promotion approval.
- [ ] AD-22: Add quarantine, expiry, revocation and rollback; enforce project/data
  boundaries and exclude target-specific secrets and authority from transfers.
- [ ] AD-23: Run application- and mechanism-separated evaluations with frozen
  memory; compare retrieval enabled/disabled and inspect negative transfer.
- [ ] AD-24: Publish per-mode ablations, failures, costs and release decisions;
  expand methods/classes only after their own held-out and safety gates pass.

**Acceptance:** a reviewed method helps on an unfamiliar implementation without
inventing its policy or leaking source-target data. Harmful/stale methods can be
revoked. Any generalisation claim identifies its test population and uncertainty;
repeating memorised scenarios is reported separately.

## Evaluation and release gates

**Primary question:** does the added layer find more independently verified
causes on unfamiliar applications within an agreed cost/false-positive envelope?

Use a frozen implemented predecessor, not the documentation baseline, as the main
comparison. A deterministic probe baseline remains useful but must not substitute
for the full predecessor agent. Fix or record application/build/config versions,
accounts, policy, starting state, tools, model/provider, prompts, sampling settings,
method memory and budgets. Configuration changes are experimental variables.

Separate external and cooperative tracks. Within cooperative mode compare the
new strategy with a baseline given the same code/telemetry; additionally report
the gain from providing extra information at all. Run ablations for relations,
state exploration, runtime feedback, minimisation, variant search and method
retrieval. Compare multi-agent scheduling only as a separate later variable.

Split by applications and mechanism families, not merely URLs. Agent-accessible
source must not contain evaluator labels, patched/vulnerable switches, benchmark
answer files or comments identifying the injected flaw; ordinary application
logic remains visible in cooperative mode. Keep held-out patch history and
solutions away from agents. Reset memory between independent trials unless a
frozen shared method set is explicitly part of the experiment.

Use at least five independently reset trials per agent configuration as an
initial protocol, not a statistical guarantee. Pair fixture variants/seeds where
appropriate, report counts and uncertainty, and predeclare larger sample needs,
regression margins and budget ceilings before examining held-out results.

| Measure | Required interpretation |
| --- | --- |
| Verified cause yield and recall | Unique independently adjudicated causes found and fraction of all in-scope seeded causes; retain blocked/unfinished cases in declared denominators. On real unknown targets report yield, not unknowable recall. |
| Verified-claim precision | True verified reports divided by all verified reports; retain false claims and report no-claim runs rather than calling them perfect precision. |
| Incremental discovery | Causes found by the advanced system but missed by the matched predecessor, alongside causes the advanced system loses. |
| Cost and latency | Actual sends, all tool/model usage, reset/analysis/replay work, wall time and available provider cost; report zero-finding runs and unavailable values honestly. |
| Proof quality | Fresh-fixture replay rate, claim-preserving reduction, number of steps and failures/flakiness; reduction length alone is not correctness. |
| Coverage and planning quality | Applicable properties/states tested, incomplete checks, meaningful paths observed and rejected assumptions; no application-wide guarantee from a partial model. |
| Transfer and change selection | Gains/regressions on unfamiliar mechanisms and held-out changes; distinguish memorisation, adaptation, negative transfer and missed regressions. |
| Safety and information boundaries | Out-of-scope sends, leaked credentials/source/data, unauthorised effects, budget overruns, unapproved replay and evaluator/memory contamination. |

Cause labels come from evaluator/maintainer adjudication, not model self-report.
Keep manifestation counts alongside cause counts and document uncertain grouping.
No weighted score may hide a safety failure or a precision regression.

**Deterministic gate:** required positive, patched and safe-exception fixtures,
policy/transport/language guards, redaction and recovery tests all pass. A missing
policy or telemetry source cannot promote a verified claim. These are suite-bound
checks, not a guarantee for all real applications.

**Agent gate:** meet the predeclared precision/recall margins and resource ceilings
on repeated held-out runs; show incremental verified discoveries and disclose
losses. Review unsuccessful trials, false confirmations and unexplained path or
cause attributions before release. Roll back a new planner/method set when its
gate fails rather than masking the result with more hypotheses or a larger budget.

## First implementation slice

Start with AD-01–AD-04 and a deliberately small application: two tenants, private
and explicitly shareable documents, related representations and one queued action.
Define normal flows and policy, but do not give the agent the failing sequence.
Include an approved independent-copy policy as a safe exception and an incomplete
observation case. Keep fixture switches and labels evaluator-only.

Next implement the bounded A1 relation/property path. Demonstrate an end-to-end
hypothesis, admitted experiment, verified effect and fresh-fixture proof before
adding the optional code adapter or a general sequence engine. Report the matched
predecessor result even if it already finds the bug; in that case this is an
integration success, not evidence of incremental discovery.

The intended PR order is fixture/protocol → relation and property contracts →
first paired validator → optional source/trace adapter and bounded sequence work
on separate branches → cause/change analysis → reviewed methods. Implementation
PRs must state satisfied gates, migration impact, actual tests and experimental
results. New metadata is additive/versioned; old receipts stay readable and must
not be replayed to populate it. Preserve `_meta["moonmcp.result"]` and managed
receipt precedence as specified in [TOOL_OUTCOMES.md](TOOL_OUTCOMES.md).

This proposal changes no runtime code, dependencies, configuration or tests. It
claims neither completion of the predecessor nor measured discovery improvements.

## Design references

Checked on 2026-10-14. These are primary design references, not evidence that the
proposed MoonMCP features work. Tool-specific APIs, licensing and versions need
rechecking when an implementation selects an adapter.

- **R1 — [Checking Security Properties of Cloud Service REST APIs, ICST 2020](https://conf.researchr.org/details/icst-2020/icst-2020-Industry/1/Checking-Security-Properties-of-Cloud-Service-REST-APIs).**
  Describes active security-property checkers added to a stateful API fuzzer.
  Application-specific policy still requires an explicit source of truth.
- **R2 — [CodeQL overview and variant analysis](https://codeql.github.com/docs/codeql-overview/about-codeql/).**
  Describes using a known vulnerability to find related code variants and
  representing source information for analysis. Static candidates still need
  applicability checks and an appropriate proof boundary.
- **R3 — [OpenTelemetry traces](https://opentelemetry.io/docs/concepts/signals/traces/).**
  Describes request paths, spans, events and links. The proposed security-decision
  observations and their completeness checks are additional application work.
- **R4 — [Hypothesis stateful tests](https://hypothesis.readthedocs.io/en/latest/stateful.html).**
  Documents rule-based state machines, preconditions and invariants. MoonMCP would
  still own admission, budgets, isolation, recovery and evidence semantics.
