# Relational vulnerability discovery roadmap

**Status:** fourth-stage proposal; documentation only. No feature, completed
prerequisite or measured discovery improvement is claimed.
**Planning baseline:** [`27702d3`](https://github.com/Moonwuk/MoonMcp/commit/27702d3037b68dbe31b960ea69fb20ba428469f2), 2026-10-14.
**Predecessors:** [PR #15](https://github.com/Moonwuk/MoonMcp/pull/15),
[PR #16](https://github.com/Moonwuk/MoonMcp/pull/16) and
[PR #17](https://github.com/Moonwuk/MoonMcp/pull/17), all open when this was prepared.
Their pinned [foundation](https://github.com/Moonwuk/MoonMcp/blob/2bfa753eaa87288c71c90fcd16eb2c740170db5e/docs/VULNERABILITY_DISCOVERY_ROADMAP.md),
[advanced](https://github.com/Moonwuk/MoonMcp/blob/da23a953f2cdaaa3481b9b2e183dab109ecff7ca/docs/ADVANCED_DISCOVERY_ROADMAP.md)
and [experimental](https://github.com/Moonwuk/MoonMcp/blob/7b662de8a22e9e4012745939e2013200adf0cf15/docs/EXPERIMENTAL_DISCOVERY_ROADMAP.md)
plans remain independently reviewable. Merging documents does not implement them.

## Decision and intended result

Add the ability to detect a forbidden **dependency**, even when each individual
request looks legitimate: a private fact changes an unauthorised observer's view,
or low-trust data changes a decision that should not depend on it.

> Approved requirement → explicit relational rule → controlled paired executions
> → observer-visible effect → independent validation → fresh-pair replay.

The first investment is a deterministic, owner-controlled, two-tenant fixture
that exposes an indirect disclosure while direct object access remains protected.
Start with one manually approved rule, not a general policy compiler or a model
of the entire application. Expand only where measured misses justify the work.

| Earlier capability | New obligation in this proposal |
| --- | --- |
| Validate an action, sequence or event order. | Compare executions whose authorised inputs agree but whose protected state differs. |
| Verify access to an object. | Verify whether an observer can distinguish a fact the policy requires to remain hidden. |
| Model related resources and causes. | Track permitted information disclosure and trusted influence across transformations. |
| Consume a known policy. | Prepare candidate rules from approved sources, expose ambiguity and validate the resulting oracle. |
| Solve input constraints or explore sequences. | Find counterexamples in small behavioural models and test their fidelity against the implementation. |

The research background is relational reasoning about multiple executions,
including information-flow hyperproperties [S1](#design-references). Initially
support only explicitly specified deterministic, finite two-execution witnesses.
This is not a general hyperproperty verifier, a differential-privacy test or a
claim that every noninterference definition can be refuted by one pair.

Reuse the [autonomy roadmap](AUTONOMY_ROADMAP.md),
[agent workflow](AGENT_WORKFLOW.md), existing project evidence/relations and the
[outcome contract](TOOL_OUTCOMES.md). Do not add a second scheduler, finding store,
unrestricted executor or self-certified verdict protocol.

## Entry gates and operating modes

Record applicable implementation commits and passing tests before enabling active
work. Offline fixture/contract work can start earlier. Dependencies are by
capability: completion of every optional engine in the earlier plans is not needed.

| Gate | Required evidence | Earlier integration point |
| --- | --- | --- |
| H1: proof and identities | Live isolated subjects, typed resources, approved policy, controls, limited verdicts and fresh-state replay. | Foundation M1–M4; advanced A1. |
| H2: bounded execution | Versioned admitted plans, actual-send budgets, credential/scope guards, cancellation, locks and evidence-backed recovery. | Foundation execution gates; advanced A3. |
| H3: controlled state | Disposable owner-approved fixtures, reset epochs, build/configuration identity, bounded setup and cleanup authority. | Advanced A3; experimental environment/recovery contract. |
| H4: fair evaluation | Frozen implemented predecessor, independent ground truth, held-out fixtures, matched capabilities/budgets and frozen method memory. | Earlier evaluation gates and miss diagnosis. |
| H5: optional observations | Approved source/runtime adapters and deployed configuration evidence with explicit coverage limits. | Advanced A2/A4; only needed for source/infrastructure-guided work. |

**Cooperative mode** supplies explicit authority to prepare paired test worlds,
read the necessary setup attestations and use synthetic data. Both worlds have
separate sessions, storage, queues and caches, or a validated reset alternative.
Application testing permission alone does not authorise copying production data,
reading cloud accounts, deploying resources or changing infrastructure.

**External mode** retains existing scoped testing. Paired claims are allowed only
when permitted test resources and observable controls establish the required
relation between states. Uncontrolled live snapshots or two different users alone
are not equivalent worlds. Otherwise retain a lead with the missing preconditions;
never invent a twin or assume hidden production state is known.

Out of initial scope: timing/cache-load channels, probabilistic mechanisms,
quantitative leakage estimates, production cloning, autonomous policy approval,
automatic cloud changes, whole-system proofs and mandatory external analysers.
These need separate methods, budgets and evidence if proposed later.

## Versioned records and result boundaries

Extend predecessor records additively; the names below are design proposals, not
new existing MCP tools or final public schemas.

| Record | Required information |
| --- | --- |
| Rule specification | Requirement/source version, approval state, observer, protected fact or trusted decision, allowed mutations, preserved inputs, observation relation, exceptions, bounds and validator version. |
| Pair manifest | World/build/configuration IDs, reset epochs, subject/resource mappings, initial-equivalence evidence, declared hidden or low-trust change, isolation and completion attestations. |
| Observation projection | Exact observable surface, raw artifact references, typed comparison, approved normalisation/mapping and excluded channels. |
| Flow boundary | Source/derived value, confidentiality and integrity labels, acting and initiating principals, transformations, declared authority changes, evidence and freshness. |
| Model snapshot | Scope, variables, abstract states/actions, unknowns, trace provenance, build/policy version, search bounds and abstraction/refinement history. |
| Relational witness | Rule and pair IDs, both receipts, precondition/control results, observer-visible distinction or forbidden decision, limitations, replay and cleanup outcomes. |

A completed action is not a valid pair; a valid pair with different responses is
not necessarily a policy violation. Keep pair validity, per-action execution,
observations, model-analysis results and finding status separate.

Preserve `_meta["moonmcp.result"]`, existing schemas and managed-receipt precedence
as defined in [TOOL_OUTCOMES.md](TOOL_OUTCOMES.md). A failed or unknown half of a
pair cannot become a clean negative or an invented completed comparison. Keep
individual receipts and useful observations, but do not promote a relational
claim until all material preconditions and controls are established.

Historical findings remain readable and retain their original proof limits.
Never reinterpret them as relationally verified or replay actions to backfill
metadata. A pair identifier coordinates evidence; it is not a distributed
transaction or permission to repeat an ambiguous mutation.

## Design requirements

### 1. Paired confidentiality and integrity experiments

For confidentiality, prepare worlds A and B with the same declared low-observer
initial view and permitted inputs, differing only in an approved protected fact
and its legitimate downstream consequences. Execute the same bounded observer
recipe, then test the declared relation between resulting observations. For the
initial isolation fixture, the relevant observations should be equal.

Specify this obligation in plain language and a typed contract, including what
is held fixed. Equivalence concerns the approved public inputs and initial state,
not the outputs whose equality is under investigation. Do not force derived
outputs to agree during setup and accidentally erase the bug.

Prove that the hidden change really occurred with a separate privileged setup
check. That check establishes a precondition, not the observer's ability to learn
the secret. Only evidence available to the declared observer can witness the
leak. In benchmarks, disclose necessary setup attestations to the runner without
exposing evaluator labels, expected verdicts or private answer data to the agent.

Require same-world A/A and B/B repeat controls, an authorised public-change
control, a patched fixture and an explicit permitted-disclosure exception. A
public control must show normal functionality still responds when it should;
an always-empty search is not a sufficient repair control. Swap world assignment
or reset order where useful to expose harness-origin differences.

Bind each pair to one build and policy version. Vulnerable-versus-patched testing
is a separate evaluator comparison, not the secret-only perturbation. Verify
session liveness independently in each world and use typed subject/object
correspondence instead of copying credentials or treating equal IDs as identity.
Do not share caches, queue namespaces, response history or fixture-control data
between worlds in a way that creates the observed channel.

Freeze comparison and normalisation rules before held-out runs. Ignore only
explicitly justified non-semantic differences. Counts, ordering, lengths, IDs
and error distinctions must not be normalised away when material to the rule.
Keep original evidence and mapping provenance. Truncated decisive output, unknown
state, uncontrolled background activity or failed convergence makes the claim
inconclusive; a fixed sleep alone is not completion evidence.

For integrity, preserve the trusted inputs and vary an authorised low-trust field.
Independently observe the protected decision or effect. The rule must identify
which dependence is forbidden: not every user influence is an integrity bug.
Include a permitted-influence control and any approved validation that allows
low-trust data to become trusted. Merely reflecting changed text is not proof
that authority or a trusted decision changed.

Report the narrow demonstrated effect. Distinguishing the existence of a private
record does not establish disclosure of its contents. A trusted decision change
does not automatically establish broader privileges. Same outputs on sampled
pairs do not prove universal confidentiality or integrity. No timing or statistical
claim may be inferred from this deterministic comparator.

### 2. Prepare executable rules without inventing policy

Start from explicitly selected owner requirements or accepted specifications.
Extract candidate assertions with exact source/version references; present the
protected fact, observers, exceptions and unresolved questions. Distinguish
approved, proposed, contradicted, stale and unsupported rules. Only an approved
rule with supported semantics may drive a verified-report path.

For example, "tenants are isolated" leaves open whether object existence, global
counts, published aggregates or exported copies are protected. Make those choices
visible. An authorised disclosure exception must identify what may be revealed,
to whom and under which conditions. Integrity exceptions likewise require an
approved reason for accepting influence from a lower-trust source. Never broaden
an exception automatically to make an observed discrepancy disappear.

Treat code, runtime behaviour and documentation as separate evidence classes.
An implementation cannot define its own correctness by observation alone, and a
documentation mismatch is not automatically a security violation. Ambiguity or
conflicting authoritative sources blocks promotion and produces a precise policy
question; it does not authorise additional target actions.

Compile only a small typed property language to registered observation/validation
primitives. No evaluation of generated source, shell or formulas with side effects.
Maintain a human-readable back-translation and source-to-rule-to-oracle mapping.
Policy approval must not expand transport scope or grant setup/mutation authority.

Test the oracle independently: known bad, repaired, allowed-exception, unknown and
vacuous cases. Mutate the rule or comparator in a reviewed local test to check
that these cases catch inverted quantifiers, omitted prerequisites and removed
exceptions. Do not use the same unreviewed generator as the evaluator of its own
translation. Budget stops and missing data must remain explicit.

Cedar Analysis [S2](#design-references) is an optional design reference for formal
policy comparison, not a mandatory dependency or an information-flow verifier.
Correct analysis of a formal policy does not establish correct translation from
natural language, enforcement at every application path or correct infrastructure.
Unsupported relational/temporal semantics must not be forced into an access-only
policy model and reported as equivalent.

### 3. Follow information and authority across components

Extend evidenced resource relations to record data derivation and the separate
flow of authority. Keep confidentiality and integrity labels independent. At each
boundary retain the initiating subject, acting service, protected input, resulting
representation, transformations and the policy that permits any disclosure or
increase in trust. Wide service permissions do not confer those permissions on
the user whose request triggered the work.

Begin with one stack and a bounded path, such as private source data, derived
index, worker and user-visible result. Join approved code/runtime information
with read-only infrastructure snapshots for entry points, events and roles.
CloudFlow [S3](#design-references) demonstrates using infrastructure definitions
to improve static data-flow analysis. The proposed live deployment binding and
relational validation still require separate MoonMCP work.

A repository configuration is intended state, not proof of deployment. Record
build/configuration identity, snapshot scope and observation time; stale snapshots,
missing permissions, sampled traces and unmanaged dependencies remain explicit
limits. No automatic credentials discovery, cloud enumeration, deployment or
policy changes follow from an imported file or discovered relation.

Distinguish declared, statically inferred and dynamically observed flow edges.
A missing check/span does not prove absence of enforcement; a static path does
not prove reachability. Synthetic markers help establish direct provenance but
cannot rule out implicit influence on branches, counts or selection. Use the
paired experiment to test a forbidden dependence and the flow evidence to guide
or qualify its explanation, not to replace independent effect observation.

Imported source, traces and infrastructure files are untrusted data. Parse with
bounded resources, do not execute templates/builds, and require explicit approval
for any isolated analyser invocation. Secret references, raw source and private
snapshots stay project-scoped with redacted model-facing views and exports.

### 4. Small behavioural models and counterexample-guided refinement

Use a narrowly scoped model of one permission lifecycle or derivation boundary,
not a digital twin claim for the full application. Record abstraction choices,
known and unknown transitions, normalisation, resets and runtime trace coverage.
Do not discard security-relevant subject, tenant, ownership or authority state.

For supported pair properties, a bounded product of two model executions can
suggest a counterexample. Map candidate actions and states to typed, admitted
recipes in the real fixture. Count model construction, solving, conformance
queries, counterexample replay and reduction in total cost. Cap states, depth,
branching, refinement iterations, memory and time; unknown or timeout is not safe.

NDSS's automata-based testing work [S4](#design-references) uses a potentially
inaccurate model to generate sequences that are tested on the implementation.
Use that model-to-test distinction here: a formal counterexample is a candidate,
not a confirmed application bug. Conversely, a model with no counterexample
cannot certify an incompletely observed implementation.

On a conclusively infeasible counterexample, preserve the concrete evidence and
refine the relevant abstraction or precondition, as motivated by counterexample
refinement [S5](#design-references). A blocked request, stale session or missing
observation does not establish infeasibility. Do not change the approved security
rule to remove a failing model path. Check refinements against earlier real traces
and hold-out conformance probes so one local failure does not erase a real path.

Keep three distinct report outcomes: real violation reproduced; no counterexample
within the declared model/search bounds; insufficient evidence or fidelity. Any
claim proved about a formal model must name that model and its assumptions, never
silently transfer the guarantee to the deployed system. Imported models and
checker output cannot bypass ordinary execution admission or expand permissions.

## Delivery plan

All **24 tasks across six milestones** are proposed and unchecked. Priorities
indicate delivery/decision order, not dates. Touchpoints are integration seams;
recheck the then-current code before choosing new module names or public schemas.

### R0 — Freeze the rule, paired fixture and baseline (P0)

**Depends on:** H4 for comparison; offline design may start earlier.
**Touchpoints:** existing fixture/evaluator harness, `moonmcp/bench.py`, evidence
records and the predecessor environment contract.

- [ ] RD-01: Pin the implemented experimental predecessor and applicable H1–H5
  evidence; freeze models, policies, budgets, data access and evaluation splits.
- [ ] RD-02: Define rule/pair/projection/witness records, validity checks, per-world
  permissions, independent reset and combined budget/recovery requirements.
- [ ] RD-03: Build synthetic two-tenant search/derived-result fixtures with hidden
  mutation attestations, repaired and allowed-disclosure modes, and normal controls.
- [ ] RD-04: Measure baseline misses and add invalid-pair, incomplete, noisy,
  constant-output and evaluator-leakage cases before tuning the new validator.

**Acceptance:** direct unauthorised object reads fail in every fixture mode, yet
independent ground truth identifies the indirect leak in the vulnerable mode.
The agent sees normal use and approved rules, not the failing route or verdict.
Both worlds reset without sharing observation state; known limitations are visible.

### R1 — Deliver a complete paired-rule validation path (P0)

**Depends on:** R0 and H1–H4. **Touchpoints:** `moonmcp/leadpipe.py`,
`moonmcp/execution.py`, `moonmcp/runs.py`, `moonmcp/web/authz.py`, proof adapters.

- [ ] RD-05: Admit paired recipes with typed identity/resource mappings, verified
  initial relation, isolated sessions and recorded convergence/reset evidence.
- [ ] RD-06: Implement a deterministic confidentiality comparator with A/A and B/B
  controls, public-change control, approved projection and fresh-pair replay.
- [ ] RD-07: Add one integrity rule for an authorised low-trust field and an
  independently observed trusted decision, including legitimate influence controls.
- [ ] RD-08: Test missing halves, stale identities, mapping errors, cancelled setup,
  truncation and unknown side effects; retain evidence without implicit replay.

**Acceptance:** prove the planted indirect disclosure and integrity violation,
reject repaired/permitted variants, and report invalid or incomplete pairs honestly.
Always-empty functionality fails the control. Claims describe only demonstrated
facts/effects, not universal noninterference or broader data access.

### R2 — Compile reviewed requirements into tested oracles (P1, conditional)

**Depends on:** R1 contracts; prioritise when policy ambiguity is a measured limit.
**Touchpoints:** policy provenance, flags/hypotheses, `moonmcp/confirm.py`, rule
admission and report adapters; optional offline policy-analysis interface.

- [ ] RD-09: Import explicitly selected requirements with exact provenance and
  prepare candidate rules, unresolved questions and explicit disclosure/trust exceptions.
- [ ] RD-10: Add versioned approval, contradiction/staleness handling, constrained
  compilation and a back-translation for human review; keep scope authority separate.
- [ ] RD-11: Validate each oracle with independently labelled good/bad/exception/
  unknown cases and local mutation checks for vacuity and incorrect translation.
- [ ] RD-12: Expose unsupported semantics and policy-analysis assumptions; compare
  generated rules with a frozen human-authored set without evaluator self-grading.

**Acceptance:** conflicting requirements cannot silently produce a verified rule.
A formal-policy result is not reported as application correctness. Source changes
invalidate dependent approval as defined; observed bugs cannot justify weakening
an exception or learning the implementation's current behaviour as ground truth.

### R3 — Connect component flows to deployed authority (P1, optional track)

**Depends on:** R1 and H5; R2 is not required when a rule is already approved.
**Touchpoints:** existing resource/cause relations, project memory, source/runtime
adapters, deployment evidence and bounded artifact storage.

- [ ] RD-13: Add separate confidentiality/integrity labels and evidenced derivation,
  initiator/actor, transformation and approved authority-change records.
- [ ] RD-14: Join one stack's code/traces with an approved read-only infrastructure
  snapshot, retaining build binding, freshness, scope and unsupported dependencies.
- [ ] RD-15: Generate a bounded pair experiment for one suspicious flow boundary;
  retain static/dynamic evidence as explanation rather than automatic confirmation.
- [ ] RD-16: Test stale deployments, missing spans, implicit-flow cases, hostile
  imported files, cross-project isolation and raw-secret export restrictions.

**Acceptance:** a real observer-visible effect validates the selected flow claim;
a static edge or marker absence alone does not. Missing cloud/source permissions
leave an explicit limitation and never trigger extra enumeration or deployment.
The HTTP-only paired path still works with all optional adapters disabled.

### R4 — Generate and refine small-model counterexamples (P2, conditional)

**Depends on:** R1 and an approved rule; H5 only for optional source guidance.
**Touchpoints:** predecessor bounded experiment language, observed-state records,
`moonmcp/web/workflow.py`, isolated model adapter and conformance fixtures.

- [ ] RD-17: Specify one bounded behavioural model with explicit unknowns, typed
  action bindings, trace provenance and security-preserving state projection.
- [ ] RD-18: Generate supported pair counterexamples, then replay through ordinary
  admitted recipes on fresh fixtures; record model and real outcomes separately.
- [ ] RD-19: Refine conclusively spurious candidates using concrete evidence without
  weakening policy; retain earlier traces and independent conformance checks.
- [ ] RD-20: Test over/under-approximation, unsupported actions, timeouts, blocked
  replays and stale builds; enforce bounds and report fidelity/coverage limitations.

**Acceptance:** reproduce a candidate in the vulnerable fixture and identify a
separate spurious model path without deleting valid behaviour. No-counterexample
results name their model and bounds; infeasibility requires evidence, not an error.
No model output bypasses executor permissions or becomes a system-wide guarantee.

### R5 — Measure incremental discovery and retain regression witnesses (P2)

**Depends on:** R1 and H4; evaluate R2–R4 only when implemented. Earlier reviewed
method gates apply to any proposed cross-project transfer.
**Touchpoints:** independent evaluator, miss diagnosis, coordinator selection,
versioned proof replay and project-scoped regression storage.

- [ ] RD-21: Run matched predecessor, predecessor-plus-comparator and full-strategy
  trials; separately evaluate source access, rule compilation and model guidance.
- [ ] RD-22: Split applications/mechanisms and rule templates; freeze oracle/model/
  memory versions, audit answer leakage and publish new as well as lost discoveries.
- [ ] RD-23: Store independently reviewed witnesses as versioned regression recipes
  with approved replay conditions, invalidation rules and redacted synthetic fixtures.
- [ ] RD-24: Publish precision, recall, replay, pair validity and full-cost results;
  promote or roll back components under predeclared margins, not lead-count growth.

**Acceptance:** added verified causes on unfamiliar fixtures justify the cost and
false-positive envelope, or the report explicitly records no gain. Regressions
remain scoped tests, not permanent safety certificates. No automatic replay on a
new build or production target follows from saving a witness.

## Evaluation and release gates

Compare the **implemented third-stage system**, not the unimplemented roadmaps,
against (a) the same coordinator with the paired comparator and (b) the full new
strategy. Give matched runs the same approved state controls, rules, observations,
model, inputs and resource ceilings. Document any predecessor adaptation and
report gains from extra capabilities separately from gains in search or detection.
Keep external and cooperative tracks distinct.

Version fixture builds/configuration, rule sources/approval, state mappings,
observation projections, prompts, sampling, analysers, model bounds and memory.
Use at least five independently reset paired trials per agent configuration as
an initial protocol, not a statistical guarantee; determine required sample size,
precision/recall/replay margins and cost ceilings before inspecting hidden cases.

Split by applications, mechanisms and policy templates, not merely routes. The
agent must not receive fixture verdict switches, answers in source/hook names,
privileged-only outputs disguised as low-observer evidence or labels from earlier
runs. Keep repaired comparisons evaluator-controlled. A fixture's expected verdict
must not be the comparator's implementation. Use separate diagnostic runs for
assisted investigations and exclude them from autonomous discovery scores.

| Measure | Required interpretation |
| --- | --- |
| Incremental verified causes | New causes and causes lost versus the matched predecessor; independent adjudication and explicit uncertain grouping. |
| Precision and recall | True/false verified claims and all eligible seeded causes; blocked/incomplete cases stay in declared denominators. Unknown real targets have yield, not measurable complete recall. |
| Pair/oracle validity | Invalid and incomplete pairs, failed controls, stale rules, translation errors and exclusions with reasons; do not improve precision by hiding failed cases. |
| Proof and fidelity | Fresh-pair replay, demonstrated observer access, exact disclosure/effect, supported exceptions, spurious-model rate and conformance limits. |
| Cost and coverage | All worlds, setup, attestation, controls, resets, model/oracle work, sends, model usage and replay; include zero-finding runs and unavailable costs explicitly. |
| Safety and boundaries | Credential/data leakage, cross-world contamination, unauthorised setup/cloud actions, overruns, ambiguous replay and legacy compatibility. |

A deterministic observed distinction must be attributed to the approved variation,
not different builds, harness metadata or a failed half. Stochastic/timing cases
are out of scope until a separately reviewed protocol defines repetition, nuisance
controls, effect size, multiple-testing handling and stopping rules. A lone latency
difference is not a substitute for such evidence.

**Deterministic gate:** required vulnerable, repaired, allowed-exception, normal-use,
invalid-pair and missing-evidence fixtures pass; outcome/credential/scope/recovery
invariants hold. Pair comparison and oracle mutation tests must catch planted
false-confirmation and always-pass/always-empty defects. These are suite-bound
checks, not proof of every information-flow policy on a real application.

**Agent gate:** meet frozen precision/recall/replay margins and total-cost ceilings
on repeated held-out trials; publish ablations and unsuccessful runs. Review false
claims, lost findings, rule misinterpretations and unexplained causal attribution.
Roll back a failing selector, oracle or model adapter rather than silently expanding
the budget, changing the protected fact or weakening the observation relation.

## First implementation PR

Deliver RD-01–RD-04 first: two synthetic tenants, private documents, normal search,
one derived result and a manually approved isolation rule. The observer can never
read the other tenant's document directly. The hidden mutation may change its
existence, while the declared public initial state remains fixed. Ground truth
identifies one forbidden derived distinction but is hidden from the agent.

Include a repair, an explicitly permitted public aggregate, a normal public-change
control, a no-op hidden mutation and an incomplete processing case. Test independent
reset and world isolation before active comparison. Then deliver RD-05/RD-06
end-to-end and RD-08's failure/recovery cases before expanding to integrity.

Subsequent investments follow diagnosed limits: R2 for unclear policies, R3 for
missing component/authority context, R4 for missed reachable states. No requirement
to build all three before demonstrating the first additional discovery. Each code
PR must list satisfied gates, compatibility/migration decisions, actual tests and
measured outcomes. This proposal changes only documentation; it performs no target
experiments and delivers no runtime, dependency, configuration or test changes.

## Design references

Primary research and official references checked on 2026-10-14. They motivate
techniques, not MoonMCP efficacy. Recheck versions, APIs and licensing before any
adapter is selected; these references add no runtime dependency.

- **S1 — [Logics and Algorithms for Hyperproperties](https://arxiv.org/html/2501.08063v1).**
  Discusses security requirements over multiple executions and formal analysis.
  This roadmap deliberately restricts its first validator to finite deterministic
  paired witnesses rather than all information-flow or hyperproperty semantics.
- **S2 — [Introducing Cedar Analysis](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/).**
  Describes formal policy comparison and symbolic compilation. Natural-language
  translation, relational rules and application enforcement remain separate issues.
- **S3 — [CloudFlow](https://www.usenix.org/conference/usenixsecurity25/presentation/raffa).**
  Uses infrastructure definitions to identify events, permissions and entry points
  for static analysis. Dynamic reachability and current deployment need separate evidence.
- **S4 — [Automata-Based Automated Detection of State Machine Bugs in Protocol Implementations](https://www.ndss-symposium.org/ndss-paper/automata-based-automated-detection-of-state-machine-bugs-in-protocol-implementations/).**
  Generates tests from potentially inaccurate models and checks real implementations.
  Its protocol results do not establish general applicability to web business logic.
- **S5 — [Generating Abstract Explanations of Spurious Counterexamples in C Programs](https://www.microsoft.com/en-us/research/publication/generating-abstract-explanations-of-spurious-counterexamples-in-c-programs/).**
  Motivates evidence-guided abstraction refinement. Adapting it to learned web
  behaviour requires explicit assumptions, conformance checks and bounded claims.
