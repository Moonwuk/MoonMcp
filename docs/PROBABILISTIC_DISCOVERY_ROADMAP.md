# Probabilistic and cumulative vulnerability discovery roadmap

**Status:** fifth-stage proposal; documentation only. No capability, completed
implementation gate or measured improvement is delivered by this document.
**Planning baseline:** [`40ef2bc`](https://github.com/Moonwuk/MoonMcp/commit/40ef2bc662337c32707372d3e2475404f3019879), 2026-10-14.
**Direct predecessor:** [relational discovery](RELATIONAL_DISCOVERY_ROADMAP.md),
introduced in [PR #18](https://github.com/Moonwuk/MoonMcp/pull/18), merged at this
baseline. Its [pinned version](https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/docs/RELATIONAL_DISCOVERY_ROADMAP.md)
limits its first validator to deterministic paired witnesses. Merging a roadmap
is not evidence that its implementation exists or its acceptance gates pass.

## Decision and scope

Investigate forbidden information or influence in distributions and complete
interaction histories, not just different individual responses. Start with a
small synthetic mechanism whose outcome probabilities are independently known,
a fixed recipe and a fixed confirmation sample size. Add adaptive techniques
only after the fixed-horizon evidence path is calibrated.

> Approved rule → exploratory candidate → frozen protocol → fresh observations
> → valid statistical evidence → observer-limited claim → independent replication.

This extends the earlier [foundation](VULNERABILITY_DISCOVERY_ROADMAP.md),
[advanced](ADVANCED_DISCOVERY_ROADMAP.md),
[experimental](EXPERIMENTAL_DISCOVERY_ROADMAP.md) and relational plans; it does
not replace their scope guards, coordinator, proof records or findings store.
Reuse the [agent workflow](AGENT_WORKFLOW.md) and
[execution outcome contract](TOOL_OUTCOMES.md).

| Earlier capability | Additional question |
| --- | --- |
| Compare deterministic paired observations. | Does protected state change the distribution of allowed observations? |
| Compose actions to reach a forbidden effect. | Does a whole transcript reveal a fact that its individual responses do not? |
| Preserve an observer's evidence boundary. | Can a frozen observer actually distinguish fresh hidden cases under declared capabilities? |
| Bound requests and model/tool use. | Is false-confirmation risk controlled across selected hypotheses, repeated looks and restarts? |
| Reproduce one witnessed violation. | Does an estimated effect replicate under the same protocol with uncertainty and failures retained? |

A distribution difference is not automatically a security violation: establish
an approved confidentiality/integrity rule, applicable exceptions and the relevant
observer or protected decision. A valid direct witness of forbidden access/action
remains a finding even when rare; this layer must not require repeated harm to
accept it. Statistical methods are needed for claims based on patterns or rates,
not as a mandatory replacement for existing class-specific proof.

Initial non-goals: a universal statistical test, unrestricted repeated querying,
production load generation, secret reconstruction at scale, automatic policy
approval, general differential-privacy certification and mandatory new dependencies.
Timing and AI-agent testing are optional, separately gated extensions, not
prerequisites for the first useful result.

## Entry gates and operating modes

Attach implementation commits and passing tests for the applicable gates. The
whole earlier roadmap chain need not be implemented; dependencies are by capability.
Offline fixture and contract design may start before active testing is enabled.

| Gate | Required evidence | Integration dependency |
| --- | --- | --- |
| J1: valid relational setup | Approved rule, observer/subject mapping, protected variation, public-state controls, isolated worlds and trustworthy setup attestations. | Relational R0/R1. |
| J2: admitted execution | Metered recipes, per-destination credentials, bounded setup/cleanup, cancellation, session locks and evidence-backed recovery. | Earlier executor and run gates. |
| J3: valid sampling | Defined independent unit or dependence model, reset/convergence evidence, pinned environment and accessible observation surface. | Relational pair records plus this plan's protocol admission. |
| J4: independent evaluation | Ground truth, hidden labels, frozen predecessor/model/memory, held-out mechanisms and recorded costs. | Earlier evaluation and miss diagnosis. |
| J5: specialist authority | Explicit local timing or sandboxed AI-app permission, supported transport/measurement contracts and external-effect isolation. | Only the relevant P5 extension. |

**Cooperative mode** uses approved disposable fixtures and synthetic data. Keep
observer-visible outputs separate from privileged setup checks and evaluator
answers. Randomness/seeds used for reproducibility must not become a label channel.
Do not clone production data or share storage, cookies or hidden control metadata
between worlds merely to simplify sampling.

**External mode** requires an observable, authorised design that supports the
claimed contrast and sampling assumptions. No unseen protected-state labels,
independent resets or server observations may be presumed. Otherwise report an
exploratory lead or unsupported/inconclusive test, not an invented controlled
experiment. Rate limits and target policy override desired statistical power.

## Contracts and compatibility

The following are proposed versioned extensions to existing records, not existing
public tools or approved final schemas. Recheck code seams at implementation time.

| Record | Additional information |
| --- | --- |
| Statistical protocol | Rule/pair versions, hypothesis family, observer, contrast, allowed effect, power target, sampling unit, dependence assumptions, exclusions, estimator/test, error allocation, sample size or valid stopping rule, analysis version. |
| Episode manifest | One feasible history with subjects, state/reset/build versions, bounded query policy, transcript projection, prior observations and target-enforced limits. |
| Frozen candidate | Recipe, feature/observer model, discovery-data provenance, permitted training knowledge, thresholds and confirmation-data access boundary. |
| Evidence ledger | Project/campaign and hypothesis IDs, protocol hashes, allocations, looked-at batches, dataset/split lineage, aborted/failed attempts, concurrency and restart events. |
| Statistical witness | Raw bounded artifacts, execution receipts, valid/invalid units, effect estimate/interval, calibrated decision, controls, assumptions, observer limitations and replication outcomes. |

Keep execution outcome, sampling validity, statistical result and security verdict
separate. `completed` does not mean enough valid data; a statistically significant
feature does not establish the required policy violation. A statistical no-rejection
is not proof of equality or application safety. Equivalence claims need a separate
approved margin and supported method; the initial verifier must not infer them.

Preserve `_meta["moonmcp.result"]`, existing schemas and managed-receipt precedence
from [TOOL_OUTCOMES.md](TOOL_OUTCOMES.md). Missing batches, cancelled setup and unknown
target effects retain their actual outcomes. Never replay historical calls to
populate new fields or silently promote old signals to statistical proof.

Lost/missing measurements are not zero, ordinary responses or harmless outliers.
An observed target error can be a predefined response category if the contract
supports it; an unknown controller outcome cannot. Differential failures, truncation
or censoring can invalidate inference and must not be silently dropped. Preserve
all attempts, including rejected candidates and failed independent replications.

## Design requirements

### 1. Separate search from fixed-horizon confirmation

Exploration may choose recipes and observer-visible features on discovery data.
Confirmation uses a frozen candidate, fresh data and a predeclared decision rule.
Changing a feature, normalisation, direction, threshold or model after inspecting
confirmation results creates another selected test, not a revision of the same
successful proof. Previously inspected holdout data cannot become fresh again.
The separation of dataset search from property testing in DP-Auditorium
[T1](#design-references) is a design precedent, not a generic API security oracle.

Start with a bounded scalar/categorical observation. For example, estimate the
absolute difference in the probability of a registered event under two controlled
protected states. An approved zero-dependence rule has a zero allowed difference;
a permitted nonzero difference must come from policy, not the agent. A minimum
effect used for sample-size/power planning is not permission to ignore smaller
true violations or weaken the rule after testing.

Freeze the null/alternative, effect units, uncertainty method, controls and exact
independent unit. Select a fixed sample size from power calculations or independently
calibrated simulations for declared effects and error bounds. Do not reuse a small
agent-trial count such as five as a justification for statistical sample size.
Include nuisance distributions and the domain where the selected method is valid.
No finite-budget test is guaranteed to detect every arbitrarily small departure.

Randomise or block world order as specified, preserve same-world and authorised
public-change controls, and verify the hidden change and completion separately.
Do not claim independent observations just because they are separate HTTP calls.
Shared caches, user sessions, queue state or a common model conversation can make
an episode the sampling unit. Seeds alone do not establish independence; deliberate
paired randomness must be reflected in the analysis rather than treated as two
independent samples. Unmodelled dependence or drift makes the test unsupported.

Initially preregister a finite family with valid per-test error allocations whose
sum is at most a campaign bound. A union bound gives a conservative family-level
bound when the individual tests remain valid; independent tests are not required
for that arithmetic, but valid sampling and selection assumptions are. This is
not the same as the proportion of false reports among all reports. Record both
empirical report precision and the claimed testing-error guarantee separately.
A p-value is not the probability that the vulnerability claim is false.

A finding needs a valid relational setup, an approved violated rule, supported
inference and appropriate observed effect. Report the actual effect and its
uncertainty, not an LLM-generated confidence score. Do not convert failed rejection
into safety, a generic distribution distance into leaked bits, or an existence
signal into content access. Direct deterministic proofs keep their own pathway.

### 2. Test complete, feasible episodes

Some leakage is in relationships between responses. An evaluator-owned toy example
can use two individually uniform bits whose equality depends on a hidden bit:
both marginals match, while the transcript reveals that bit. Include a repaired
joint distribution and a permitted-disclosure policy. This is a fixture design,
not an instruction to target real secrets or a claim about an existing service.

Define the full episode before checking cumulative effects: initial state, allowed
queries, observation history, subject capabilities, session lifetime and budgets.
Do not stitch observations from incompatible sessions/builds or insert a privileged
reset between steps the observer must obtain in one history. Reset independently
between replicate episodes, preserving within-episode dependencies intentionally.
Target-enforced accounting that persists beyond an episode remains part of the
threat model; fixture reset privileges are not attributed to an outside observer.

Start with fixed-length recipes. Later allow a frozen bounded query policy that
chooses the next permitted action from the current transcript; include its selection
and stopping behaviour in the definition of the sampled episode. Cross-episode
policy changes require new confirmation or a separately justified adaptive design.
Adaptive action selection within an episode and optional stopping of statistical
sampling across episodes are different problems and need separate checks.

The DP composition literature [T4](#design-references) motivates considering an
entire interaction, but its guarantees require the stated DP assumptions. Generic
API comparisons do not automatically define epsilon/delta or a privacy budget.
A dedicated DP adapter would need an approved neighbour relation, mechanism version,
guarantee/parameters, sampling model and relevant composition rule. It is outside
the initial comparator; never label ordinary noise as a DP implementation.

### 3. Validate the observer blindly on new cases

After selecting a feature or classifier, freeze preprocessing, parameters, decision
thresholds, query policy and assumed auxiliary knowledge. An independent evaluator
then prepares new hidden-state episodes. The observer receives only its declared
application view, not world IDs, evaluator seeds, privileged logs or correctness
labels. Initial binary fixtures use a balanced hidden-state design; other settings
must state a justified no-information baseline and class-specific error rates.

Keep discovery, tuning and confirmation/replication partitions separate by episode
and independently reset fixture, not random rows from one transcript. Freeze model
memory and training inputs. Disclose any privileged labelled preparation, known
mechanism or surrogate access; laboratory discrimination under those assumptions
does not demonstrate that an ordinary external user can train the same observer.

Report accuracy or an appropriate decision-performance measure with uncertainty,
baseline, costs and all errors. Repeatedly selecting the best observer or threshold
on the test set is another multiplicity problem. Failure of one observer is not
proof that no observer can learn the fact; success establishes only its demonstrated
fact, capabilities and environment. Black-box f-DP research linking estimation
and classification [T3](#design-references) is a methodological reference, not a
general guarantee for MoonMCP's arbitrary target distributions.

Replication uses fresh cases and the same frozen protocol. Record unsuccessful
replications and any justified environmental differences; do not rerun until one
passes and hide the rest. Statistical repeatability concerns the supported effect
and uncertainty, not byte-identical responses or an obligation that every finite
replication must reject the null.

### 4. Persist testing history before adding adaptive stopping

From the first active comparator, allocate the declared hypothesis family and
record inspected data durably. Maintain separate accounts for requests/resources,
statistical testing error and any explicitly defined target privacy budget. None
can substitute for the others. A fresh run, task name, worker or branch must not
silently reset an exhausted confirmation allocation or hide earlier looks.

Record all analyst/agent looks that can change decisions, including raw evidence
exposed before a planned analysis. Use immutable split/candidate hashes, project
scope, lineage and atomic reservations. For a simple initial policy, retain an
allocation once confirmation data could have been inspected; do not refund it
because the test was aborted, renamed or inconvenient. Other reuse/reallocation
rules require a justified reviewed method, not scheduler discretion.

Bounded fixed-horizon confirmation comes first. Only then consider time-uniform
confidence sequences or another valid sequential method under explicit assumptions
[T2](#design-references). A stopping-time guarantee does not permit arbitrary
hypothesis changes, invalid dependence assumptions or unrestricted reuse of data.
The specialised sequential f-DP auditors in [T5](#design-references) are an optional
research reference, not a ready-to-use universal verifier.

Pause/resume must preserve sufficient analysis state, inspected batches, allocations
and execution uncertainty. Concurrent workers share the declared family ledger.
If lineage is missing or statistical validity cannot be reconstructed, block
confirmation rather than reset the ledger. Changed target/model versions or drift
must be recorded and handled by the preregistered rule, not silently pooled.

### 5. Optional timing and AI-application adapters

**Timing:** start on a local or dedicated owner-controlled fixture. Define the
observable clock, platform/build, warm-up, query order, drift/dependence controls,
censoring and stopping rule. A server-only difference cannot be reported as a
remotely observable channel. The measurement approach of dudect
[T6](#design-references) is a reference for local timing studies, not a remote
scanner or a statistical threshold to copy without validation. Never generate
production load or recover real secrets merely to increase a test's power.

**AI applications:** use sandboxed tools, synthetic documents/data and an explicit
boundary between legitimate user authority and untrusted material. Observe actual
forbidden tool effects or state, not merely text that claims an action occurred.
Record model/provider/version, decoding configuration, tools, memory/reset policy,
task success and safety outcomes. A refusal-only or broken agent is not a successful
utility-preserving defence. AgentDojo [T7](#design-references) provides a design
reference for evaluating tool agents over untrusted data, not a guarantee for a
selected application or provider.

Both adapters require J5 and their own calibration/safety gate. The investigated
content cannot issue instructions to MoonMCP or expand the executor's capabilities.
Keep model-facing evidence limited and raw material project-scoped. Provider/model
drift, unavailable metering, unsafe side effects or incomplete tool observations
block the affected claim. One verified prohibited action can establish an incident;
estimating its rate needs the separately valid sampling protocol.

## Delivery plan

All **28 tasks across seven milestones** are proposed and unchecked. Priorities
indicate delivery order, not dates. Touchpoints are integration seams to revalidate
against the implementation before choosing new paths or public schemas.

### P0 — Freeze the statistical question and fixture baseline (P0)

**Depends on:** J4 for comparative claims; offline work may start earlier.
**Touchpoints:** `moonmcp/bench.py`, independent fixtures/evaluator, relational
rule/pair records and run evidence.

- [ ] PD-01: Pin the implemented relational predecessor and J1–J4 evidence; freeze
  approved claims, inputs, models, budgets, method memory and evaluation boundaries.
- [ ] PD-02: Define protocol/episode/ledger/witness schemas, null/alternative,
  effect and power targets, sampling assumptions and fixed-family error accounting.
- [ ] PD-03: Build finite-outcome stochastic fixtures with independently known
  probabilities, repaired/allowed variants and valid normal-use controls.
- [ ] PD-04: Add harness-label leakage, no-op hidden changes, dependence, missing
  data and noisy-safe cases; record baseline misses before tuning the verifier.

**Acceptance:** evaluator ground truth is independent of the candidate comparator.
Direct private-object reads fail in every fixture mode; only the declared hidden
influence differs. Noise alone and invalid world preparation are not findings.

### P1 — Complete fixed-horizon statistical confirmation (P0)

**Depends on:** P0 and J1–J4. **Touchpoints:** `moonmcp/leadpipe.py`,
`moonmcp/confirm.py`, `moonmcp/execution.py`, proof adapters and durable run storage.

- [ ] PD-05: Freeze candidate recipes/features after discovery; admit fresh
  confirmation partitions and a predeclared fixed sample size/decision rule.
- [ ] PD-06: Implement one bounded scalar/categorical comparator with calibrated
  uncertainty, controls and explicit unsupported-dependence/missingness outcomes.
- [ ] PD-07: Add the initial durable finite-family ledger before active confirmation;
  atomically record allocations, inspected batches, failed attempts and provenance.
- [ ] PD-08: Test sampling boundaries, stale identities/builds, receipt failure,
  cancellation and direct-proof coexistence without statistical backfill or replay.

**Acceptance:** the known stochastic departure is detected with the preregistered
power, while null-case false-confirmation behaviour meets the calibrated gate.
Controls and execution outcomes remain visible. No-rejection never means safe.

### P2 — Validate cumulative transcripts (P1)

**Depends on:** P1 and valid stateful episode execution under J2/J3.
**Touchpoints:** bounded recipes, `moonmcp/web/workflow.py`, transcript artifacts,
relational projections and the existing coordinator.

- [ ] PD-09: Define one feasible fixed-length episode with scoped identities,
  target limits, state lineage and explicit between-episode reset conditions.
- [ ] PD-10: Add the equal-marginals/different-joint fixture and analyse a registered
  transcript feature against repaired and permitted-disclosure controls.
- [ ] PD-11: Reject incompatible-history joins and privileged mid-episode resets;
  retain within-episode dependencies instead of inflating the sample count.
- [ ] PD-12: Admit one frozen bounded adaptive query policy only after its episode
  semantics, total cost and failure handling have independent tests.

**Acceptance:** establish the narrow transcript-level disclosure with reproducible
controls. Marginal equality is not treated as transcript safety; adaptive episode
success does not authorise optional statistical stopping or unlimited requests.

### P3 — Add blind observer validation and independent replication (P1)

**Depends on:** P1; P2 when validating a multi-step observer.
**Touchpoints:** evaluator/split isolation, frozen candidate artifacts and reports.

- [ ] PD-13: Freeze an observer and its auxiliary/training knowledge; isolate
  discovery, tuning, test and replication episodes and model memory.
- [ ] PD-14: Implement evaluator-owned hidden assignments, accessible-output-only
  decisions, justified baselines and uncertainty/error reporting.
- [ ] PD-15: Test label leakage through fixture IDs, ordering, seeds, metadata,
  privileged setup and shared transcript rows; block contaminated conclusions.
- [ ] PD-16: Replicate under a preregistered fresh-data protocol, retaining failures
  and distinguishing laboratory knowledge from external-user capabilities.

**Acceptance:** a permitted observer distinguishes the planted fact on unseen cases
without receiving the answer through the harness. Safe cases and weaker observers
are not overclaimed; all repetition costs and inconclusive runs remain visible.

### P4 — Support justified sequential sampling and resilient error accounting (P2)

**Depends on:** P1 ledger and P3 split discipline; separate statistical review.
**Touchpoints:** `moonmcp/runs.py`, atomic storage, analysis adapter and recovery tests.

- [ ] PD-17: Specify one supported time-uniform method, assumptions, evidence state
  and stopping rules; retain the fixed-horizon verifier as a usable default.
- [ ] PD-18: Preserve family allocation and all inspection lineage across restarts,
  workers, renamed hypotheses, aborts and data reuse; block unexplained gaps.
- [ ] PD-19: Stress long all-null campaigns, deliberate peeking, selection changes,
  correlated episodes and drift against the method's actual assumptions.
- [ ] PD-20: Compare full sampling/analysis cost and detection power with the fixed
  design; introduce no automatic resource increases to force a positive result.

**Acceptance:** stopping and restart tests preserve the stated error guarantee under
its assumptions; invalid dependence/lineage blocks inference. Sequential sampling
is shipped only with demonstrated validity and disclosed gains or regressions.

### P5 — Evaluate specialist channels separately (P2, optional)

**Depends on:** P1/P3 and J5 per adapter; P4 only for sequential claims.
**Touchpoints:** optional measurement/tool registry, isolated fixtures and receipts.

- [ ] PD-21: Specify one local/dedicated timing protocol with observable-clock,
  platform, nuisance, dependence and censoring controls; forbid implicit load testing.
- [ ] PD-22: Validate its positive, constant/irrelevant-variation and drift cases;
  keep local diagnostic evidence separate from demonstrated remote observability.
- [ ] PD-23: Define one sandboxed AI-app rule, synthetic untrusted-data variation,
  independent tool-effect observer and matched legitimate-task utility controls.
- [ ] PD-24: Test provider drift, memory contamination, metering gaps and unavailable
  effects; preserve actual incidents separately from estimated failure rates.

**Acceptance:** each enabled adapter passes its own safety and measurement tests.
No shared universal threshold, secret extraction, real external tool effect or
production-load experiment is introduced by enabling the core comparator.

### P6 — Measure useful discovery and maintain calibration (P2)

**Depends on:** P1 and J4; evaluate other milestones only when implemented.
**Touchpoints:** independent benchmark harness, miss diagnosis, frozen reports
and reviewed project-scoped method/regression records.

- [ ] PD-25: Compare implemented predecessor, predecessor-plus-comparator and full
  strategy with matched capabilities, inputs, models and complete cost ceilings.
- [ ] PD-26: Split by applications, mechanism and protocol templates; freeze all
  observer/analysis versions and audit answer leakage and post-selection reuse.
- [ ] PD-27: Measure whole-campaign false confirmations, effect-specific power,
  replication and incremental causes, including lost findings and failed runs.
- [ ] PD-28: Publish assumptions, calibration uncertainty, ablations and rollback
  decisions; version changes and invalidate stale claims without automatic replay.

**Acceptance:** meet predeclared power/error/replay/cost margins on held-out cases,
or explicitly report no useful improvement. Neither more samples nor stronger
significance language substitutes for verified new causes and working controls.

## Evaluation and release gates

Use the **implemented relational system** as the predecessor, not a document or
probe-only substitute. Compare its native workflow, the same coordinator with
this comparator, and the full new strategy; document any adaptation. Match allowed
world preparation, rules, transcripts, model/provider, tool versions, seeds/splits,
query ceilings and data access. Report extra-information/capability gains separately
from strategy gains. External and cooperative results remain separate tracks.

Distinguish sample size within a statistical experiment from the number of repeated
agent/campaign trials used to evaluate the product. Choose both from declared
precision/power/calibration objectives; do not assert a universal minimum trial
count suffices. Independent replication and many-hypothesis null campaigns require
their own planned counts and uncertainty, not just a few successful demonstrations.

Use finite fixtures with independently calculable distributions to check the
comparator, plus distinct held-out stochastic mechanisms and applications to test
transfer. Classify fixtures and invalid exclusions before freezing denominators.
Keep test labels, mechanism answer switches and randomness seeds out of observer
views. Synthetic success is not evidence of effectiveness on arbitrary real targets.

| Measure | Required report |
| --- | --- |
| Useful discovery | New and lost independently adjudicated causes versus the predecessor, manifestation counts and uncertain grouping. |
| Precision and recall | True/false verified reports and all eligible planted causes; blocked/unfinished eligible cases remain in declared denominators. Real targets with unknown truth have yield, not complete recall. |
| Error calibration | Per-test and whole-campaign false-confirmation rates/uncertainty, family definition, selection/stopping method and supported assumptions; not a posterior probability of a bug. |
| Power and sensitivity | Detection rates at preregistered effects, missed effects and conditions; the detectable effect is not an acceptable-leakage policy threshold. |
| Observer and replication | Baselines, accuracy/error intervals, accessible evidence, auxiliary knowledge, fresh-data replication and failed/inconclusive repeats. |
| Cost and validity | All setup, sampling, controls, resets, training, analysis/model use, ledger/replication work; zero-finding runs, invalid units, drift and unavailable costs. |
| Safety and recovery | Scope/credential violations, target-load limits, unapproved effects, hidden resets, data contamination and forgotten error allocations after restart. |

**Deterministic software gate:** protocol validation, exact/reference calculations,
ledger transitions, isolation, guard/recovery and compatibility fixtures pass.
Required stochastic tests cannot reasonably demand every random run be positive
or every safe campaign contain zero false alarms. Independently validate theoretical
or exact finite-case calibration where available and use a frozen Monte Carlo
acceptance procedure with stated uncertainty/tolerance for empirical checks.

**Statistical and agent gate:** predeclare a supported null domain, campaign error
bound, calibration tolerance, effect-specific power, replication and resource
criteria before looking at held-out results. Report simultaneous/comparative testing
choices as relevant. Examine all-null long campaigns, mixed campaigns and adversarial
peeking/restart cases, not only individually safe tests. One-run clean behaviour is
not an error guarantee; no-rejection on one classifier is not privacy certification.

When a gate fails, roll back the analysis/selector version or report unsupported
conditions. Do not rescue the result by deleting awkward observations, resetting
the error family, changing the protected fact, weakening policy or silently raising
request budgets. Changed environment/model versions need explicit revalidation;
saving a witness does not authorise future active replay.

## First implementation PR

Start with PD-01–PD-04: a finite-output, synthetic two-tenant mechanism where direct
private-object reads fail and a hidden fact changes a permitted result's event
probability only in the vulnerable variant. The repaired variant remains random
but independent of that fact; another variant permits the disclosed fact by policy.
Add normal-use, no-op mutation, missing-observation and harness-only-signal controls.

Then deliver PD-05–PD-08: one frozen feature, fixed sample size, independent data,
valid controls, a minimal persistent finite-family ledger and narrow proof output.
Add cumulative transcripts and blind validation next. Sequential sampling, timing
and AI-app adapters are not requirements to demonstrate the first useful discovery.
Every implementation PR must list satisfied gates, migrations, actual tests and
measurement. This proposal changes only Markdown: no runtime, configuration,
dependency or test changes, target experiments or benchmark results are delivered.

## Design references

Primary/official sources checked on 2026-10-14. They motivate methods and limitations,
not MoonMCP efficacy; APIs, assumptions and licensing need review before adoption.
No cited system is a mandatory dependency through this proposal.

- **T1 — [DP-Auditorium](https://research.google/blog/dp-auditorium-a-flexible-library-for-auditing-differential-privacy/).**
  Separates dataset finding and property testing of specified DP guarantees. A
  failed attempt to find a violation does not certify the mechanism; this plan's
  initial generic comparator does not inherit a DP guarantee.
- **T2 — [Time-uniform, nonparametric, nonasymptotic confidence sequences](https://arxiv.org/abs/1810.08240).**
  Develops confidence sequences valid across time under stated conditions. Optional
  stopping validity is not permission to change hypotheses or ignore dependence.
- **T3 — [General-Purpose f-DP Estimation and Auditing in a Black-Box Setting](https://www.usenix.org/conference/usenixsecurity25/presentation/askin).**
  Combines statistical estimation and classification theory for f-DP auditing.
  Observer capabilities, train/test separation and arbitrary-API applicability
  remain explicit responsibilities of the proposed MoonMCP adapter.
- **T4 — [The Composition Theorem for Differential Privacy](https://proceedings.mlr.press/v37/kairouz15.html).**
  Studies privacy loss across adaptive interactions for mechanisms under DP
  assumptions. It does not assign a privacy budget to an unspecified noisy API.
- **T5 — [Sequential Auditing for f-Differential Privacy](https://www.usenix.org/conference/usenixsecurity26/presentation/kutta).**
  Describes sample-adaptive f-DP auditors with statistical guarantees. Treat this
  as specialised research to evaluate, not evidence of a working MoonMCP feature.
- **T6 — [dudect](https://github.com/oreparaz/dudect).**
  Uses execution-time measurements and statistics for local constant-time testing.
  Remote observability and the campaign-level testing policy require separate work;
  do not transplant example thresholds as universal guarantees.
- **T7 — [AgentDojo](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html).**
  Evaluates tool agents over untrusted data with realistic task and security tests.
  The proposed adapter must still verify actual effects, utility, sampling validity
  and isolation rather than treating generated text as proof of an action.
