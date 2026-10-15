# Faithful research environments roadmap

**Status:** proposal; documentation only. **Prepared:** 2026-10-15.
**Reviewed baseline:** [`40ef2bc`](https://github.com/Moonwuk/MoonMcp/commit/40ef2bc662337c32707372d3e2475404f3019879).
Read the accompanying [capability audit](CAPABILITY_AUDIT_2026-10-15.md) before
implementation. Existing Docker, browser, request, memory and execution primitives
must be reused or deliberately hardened, not presented as absent.

## Decision

Enable MoonMCP to prepare a permitted real application for a meaningful experiment
and establish that the experiment still tests the application's actual security
boundary. A successful container start or generated test is not that result.

> Inspect approved project material → propose a bounded setup recipe → admit it
> → reproduce normal use → validate harness fidelity → test through a real entry
> point → independently reproduce the effect → clean up and preserve limitations.

Start with one agreed web framework, database and worker/queue combination. Select
the concrete versions from an owner-approved fixture and pin them in the first
implementation PR. Do not promise arbitrary-repository onboarding, introduce a
mandatory platform dependency, or require every earlier research engine first.

The aim is less manual preparation and more correctly testable functions, with
independently verified discoveries as a separate outcome. Expected benefits are
hypotheses until measured. Existing security detectors remain useful even when
this optional environment layer is disabled.

## Reuse, then extend

The [audit](CAPABILITY_AUDIT_2026-10-15.md) provides pinned source evidence and
limitations for these integration seams:

| Existing piece | Reuse | New work, not already established |
| --- | --- | --- |
| `DockerSandbox` / `sandbox_exec` | Existing lifecycle and optional execution integration. | Hardened admission, pinned images, enforced egress, durable leases, process termination, app-specific setup and fidelity checks. |
| `registry.py`, `execution.py`, `runs.py` | Tool policies, guarded dispatch, HTTP reservations, receipts, leases, artifacts and recovery. | Approved environment capabilities and local resource accounting; never hide an unmetered adapter behind a managed wrapper. |
| `auth.py`, `web/authz.py` | Existing authenticated probes and explicit alternative identities. | Synthetic setup subjects, named session mappings and tested separation between privileged preparation and the assessed user. |
| `web/browser.py`, `intercept.py` | Normal-use action primitives, structured requests and history. | Fix/admit routing and credential boundaries, retain full necessary recipes and verify dependencies/convergence. Prefer HTTP-only operation until browser gates pass. |
| `recon/sast.py`, `recon/openapi.py`, source tests/docs | Local source hints and endpoint inventory. | Derive and validate a functioning preparation plan; these hints do not prove policy, reachability or deployment state. |
| `leadpipe.py`, flags and findings | Existing leads, criteria, observations and report linkage. | Executed, independently observed proof under stated environment assumptions, rather than plan text or a generated driver's crash. |
| `bench.py` and existing CI | Offline real-tool fixtures and installed-wheel/recovery test patterns. | Unfamiliar application preparation, harness-fidelity cases and end-to-end effort/discovery evaluation. |

Related plans: [foundation](VULNERABILITY_DISCOVERY_ROADMAP.md),
[advanced](ADVANCED_DISCOVERY_ROADMAP.md),
[experimental](EXPERIMENTAL_DISCOVERY_ROADMAP.md),
[relational](RELATIONAL_DISCOVERY_ROADMAP.md), and the
[pinned probabilistic proposal](https://github.com/Moonwuk/MoonMcp/blob/4566c6fa38c13cf4bc7646ac5bc50d8572017d17/docs/PROBABILISTIC_DISCOVERY_ROADMAP.md).
This is a parallel practical track. Dependencies below are concrete capabilities,
not completion of all those documents or their optional model/statistical modules.

## Preconditions and authority

Before any active setup, record the authorised repository revision, owner-approved
test environment, synthetic-data policy, available resources and actions that may
change state. Source-read permission does not authorise execution of build scripts,
image pulls, database migrations, cloud deployment or live-target changes.

Require a supported class-specific proof path, explicit expected security rule,
live test identities, bounded execution, evidence-backed recovery and an independent
evaluator for claims of improvement. A detector returning a plan or a generic
confirmation score does not satisfy the proof requirement by itself.

Separate a read-only planner, a narrowly authorised environment controller and the
assessed user's actions. Each has different capabilities. The controller may know
synthetic setup facts that the user cannot; controller observations establish
preconditions, not disclosure to that user. Environment authority must expire and
remain bound to the project, build and disposable resources.

Repository files, tests, comments, configuration, dependency metadata and service
responses are untrusted data. They may suggest a recipe, never grant permission,
change the investigation goal or directly issue commands to MoonMCP. No production
clone, host Docker socket mount into the tested application, inherited personal
credentials or automatic network expansion is part of this proposal.

External assessments without project/setup authority continue through existing
scoped tools. Missing source, dependencies or permission is an explicit limitation,
not a reason to fabricate a representative local environment or weaken scope.

## Records and execution contract

Extend existing stores and receipts additively. The names below are proposed
records, not implemented MCP APIs. Version schemas and preserve historical reads.

| Record | Required information |
| --- | --- |
| Project manifest | Revision, declared stack/support constraints, selected source references, build inputs and dependency/image digests, approved capabilities and data boundaries. |
| Environment recipe | Typed setup steps and dependencies, resources, exact permitted fetches/commands, credential references, readiness assertions, reset/cleanup and budgets. |
| Environment receipt | Actual build/configuration, resource IDs, lease/reset epoch, preparation results, effective networking/privilege settings, failures and cleanup state. |
| Normal-flow witness | Real entry point, mapped subjects/objects, completed preconditions, intended ordinary effect and independent observation. |
| Fidelity record | Real versus simplified path, altered components/stubs/instrumentation, assumptions, controls, observed differences and limits on reachable claims. |
| Configuration scenario | Supported factor values, compatibility constraints, effective-setting evidence, application upgrade history and applicable policy version. |
| Reproduction capsule | Immutable recipe/artifact references, versions, synthetic data, subject capabilities, proof steps, independent oracle, limitations and explicit replay authorisation requirements. |

Preserve `_meta["moonmcp.result"]` and managed-receipt precedence from
[TOOL_OUTCOMES.md](TOOL_OUTCOMES.md). Preparation, test execution, fidelity,
security verdict and cleanup are separate axes. A container may start successfully
while the application never becomes ready. A test can finish while its resulting
state is unknown. Neither is a clean negative vulnerability check.

Plan hashes and artifact hashes establish identity/integrity, not truth or current
permission. Do not replay historical or ambiguous actions to fill new fields.
After interruption, reconcile existing resources and effects before an explicitly
approved retry; an environment lease is not an automatic rollback guarantee.

## Design requirements

### 1. Harden the existing runner before generating more execution

Adapt `DockerSandbox` behind a versioned runner contract with an opt-in hardened
mode and an explicit compatibility path. Do not silently redefine the existing
`sandbox_exec` behaviour or ship a second unrestricted command executor.

Pin allowed images/dependencies and verify the requested shell/runtime before use.
Prefer supported rootless/least-privilege execution; absence of those properties
must be reported, not assumed. Default application/analysis egress to none and
allow only explicitly admitted destinations through enforceable network policy.
Drop unnecessary capabilities and host access. Literal URL matching in a command
is not an acceptable substitute for controlling actual traffic.

Separate approved dependency acquisition/building from target interactions. Bound
network destinations, downloaded data and retention independently, then execute
from verified inputs. No implicit image pull, package installation, daemon access
or credentials discovery follows from an untrusted manifest. The controller, not
the untrusted application, owns narrowly scoped container lifecycle access.

Limit CPU, memory, processes, disk, output, wall time and all actual network sends.
Stream bounded output rather than buffering without limit and truncating only
when returning it. Integrate accounting at actual adapter execution points; a
single tool-call reservation cannot account for arbitrary child traffic.

Persist resource IDs and leases outside the worker process. Cancellation must stop
in-environment work, not merely terminate a local client. Independently check
process termination, stop/remove results and released resources. Reserve cleanup
capacity before mutation; if safe recovery cannot be established, quarantine or
dispose of the fixture under the pre-approved policy and retain the failure.

Browser use additionally requires the routing, installation-failure and credential
regressions identified in the audit. Initial explicit HTTP recipes avoid making
the entire browser lifecycle a prerequisite. Never disable global private-address
protection to make a local fixture work; use an explicit isolated fixture policy.

### 2. Prepare and verify normal use before security variation

The planner reads selected setup instructions, tests, schemas and examples to
propose a small dependency graph. Use registered setup primitives and admitted,
bounded build commands; keep unresolved assumptions visible. Obtain approval for
any new capability, not for every low-risk step already covered by the recipe.

Prepare synthetic tenants, users and objects, then reproduce one ordinary flow
through the real entry point. A readiness port is not proof that migrations,
workers or indexing finished. Require a semantic completion signal and verify
the actual subject, object ownership and normal effect. Store secret references
instead of copying session material into prompts or public reports.

Bound setup-repair iterations. A failure may justify a new proposal, but not
turning off authentication, validation or integrity checks to make tests run.
Any source change required for instrumentation needs its own permission and an
explicit comparison with the unmodified path. Record unsupported dependencies
instead of replacing them silently with behaviourally different stubs.

Reset application, database, queue, cache and filesystem state as required by the
scenario. Record which state is not reset. Snapshots accelerate preparation only
within demonstrated fidelity bounds; they do not make arbitrary state reachable.
Do not reuse stale session secrets or silently share state across test worlds.

### 3. Distinguish a harness defect from an application vulnerability

A generated harness is a way to reach a function in context. Compile/run success
and new coverage are diagnostic signals, not proof of valid use or a security bug.
Google's OSS-Fuzz-Gen research explicitly examines false-positive crashes and
validation against realistic entry points [U1](#design-references). That motivates
this gate; it does not establish MoonMCP's own effectiveness.

Keep a fast exploratory lane and a real-path confirmation lane. Internal calls,
stubs and synthetic states may help generate candidates, but every final claim
must identify a relevant reachable boundary and its justified preconditions.
Do not grant the assessed user a controller-only state mutation or direct internal
call merely because the harness can perform it.

Preserve middleware, authentication, validation, ownership and lifecycle checks
that matter to the claim. Conversely, malformed external input is not automatically
invalid test data: it may be exactly what the application's legitimate ingress
must handle. Distinguish adversarial data at a supported boundary from an impossible
internal object built by the harness.

Record every substitution, disabled component, time assumption and instrumentation
change. Compare relevant observations between simplified and real paths using an
approved relation, not blanket byte equality. A safe unrelated difference need not
invalidate the experiment; loss of a material security check does. Insufficient
observability leaves fidelity unknown, not implicitly passed.

Require vulnerable, repaired, benign-lookalike and normal-use controls. A repair
that disables the whole function is not evidence of preserved functionality.
A harness-only failure remains a harness defect/lead; a library-contract defect
may be reportable on its own terms without claiming remote reachability. Transfer
to the full application needs separate proof.

### 4. Explore supported configurations and application history

Read supported factors and constraints from owner-approved material. Start with a
small security-relevant set rather than arbitrary combinations of every setting.
Verify effective configuration and executing components, not just edited files.
Keep build identity, policy version, selected factors and observed behaviour in
the receipt. Contradictory/unsupported combinations are labelled, not silently
counted as product vulnerabilities.

NIST ACTS supports constrained and variable-strength interaction testing
[U2](#design-references), a possible optional selector for the matrix. Pairwise
coverage does not prove absence of higher-order faults. Report covered interactions,
unavailable configurations and selection overhead under a fixed budget.

Treat fresh installation and a supported A-to-B upgrade as distinct scenarios.
A MoonMCP store migration test does not test an application's upgrade. Run only
approved migrations on disposable data and observe the specific security property
after declared completion/consistency windows. Do not require all historical data
to equal a fresh install when the product intentionally preserves differences.
Rollback, reset and failed-upgrade handling are part of the manifest; unknown
side effects are never repaired by blindly applying the migration twice.

### 5. Make evidence independently portable

Package the minimum approved synthetic recipe, pinned inputs, environment manifest,
normal-flow witness, observer capabilities, verification steps and cleanup. Keep
raw secrets, personal source/data and privileged setup answers out of model-facing
exports. Scope grants and build permissions do not travel automatically with a
capsule. Review archive paths, referenced downloads and executable content before
import; signature/hash verification alone cannot authorise execution.

A different runner/operator should reproduce the effect without the original chat,
hidden manual preparation or access to the agent's private reasoning. Record manual
assistance explicitly. Distinguish incompatible environment, failed precondition,
missing observation, non-reproduced violation and successful proof rather than a
single pass/fail number. Saving a capsule never schedules automatic active replay.

## Delivery plan

All **24 tasks across six milestones** are proposed and unchecked. Priority is
implementation order, not a delivery date. Re-read current code before each PR.

### L0 — Reconcile capabilities and freeze the first fixture (P0)

**Depends on:** read access; no target execution required.
**Touchpoints:** capability audit, existing registry/bench/tests and run artifacts.

- [ ] ENV-01: Classify inherited tasks as reuse, extend, harden or defer; pin the
  implemented baseline and explicitly separate source evidence from test results.
- [ ] ENV-02: Specify versioned project/recipe/fidelity records and separate source,
  build, setup and assessed-user authority with explicit admission tests.
- [ ] ENV-03: Select one approved framework/database/worker stack and unfamiliar
  fixture cases, including a harness-only false positive and a repaired control.
- [ ] ENV-04: Freeze evaluator labels, end-to-end and ready-environment comparisons,
  manual-effort accounting, fidelity criteria and resource ceilings.

**Acceptance:** the first stack, normal behaviour and proof rule are explicit;
existing Docker/run/browser components are named for reuse. No document, tool name
or successful container start is accepted as a completed implementation gate.

### L1 — Harden and meter the existing environment runner (P0)

**Depends on:** L0 and approved isolated execution authority.
**Touchpoints:** `strix_adapted.py`, `registry.py`, `execution.py`, `runs.py`;
`web/browser.py` only when browser execution is included.

- [ ] ENV-05: Introduce the hardened opt-in adapter around existing Docker lifecycle,
  with pinned inputs, verified runtime, minimum privileges and enforced egress.
- [ ] ENV-06: Add bounded resource/output/process accounting and an explicit
  dependency-fetch/build phase; preserve default blocking of unmetered execution.
- [ ] ENV-07: Persist leases/resources and verify cancellation, process termination,
  cleanup outcomes and evidence-backed reconciliation after worker loss.
- [ ] ENV-08: Test hostile manifests, credential destinations, forbidden networking,
  guard failures, incompatible images and failed cleanup without touching real targets.

**Acceptance:** forbidden operations are blocked at execution, not merely rejected
by text matching. Interrupted work leaves no unaccounted live resource, or an
explicit quarantined state under policy. Legacy APIs remain compatible as declared.

### L2 — Generate a verified normal application flow (P1)

**Depends on:** L1 and an explicit security policy with a supported proof validator.
**Touchpoints:** source/OpenAPI hints, existing auth/repeater primitives, run tasks.

- [ ] ENV-09: Derive a bounded setup DAG from selected docs/tests/schema evidence,
  including missing assumptions and reviewable permitted build commands.
- [ ] ENV-10: Prepare real dependencies and synthetic subjects/objects with separate
  setup versus observer privileges, ownership evidence and secret references.
- [ ] ENV-11: Reproduce one normal public-entrypoint flow and independently verify
  readiness, session liveness, worker completion and the intended ordinary effect.
- [ ] ENV-12: Add repeatable reset and bounded repair proposals; test missing
  dependencies, stale state and attempts to weaken application checks during setup.

**Acceptance:** normal use works on fresh fixtures without hidden assistance or
removed security checks. Preparation failure is explicit. HTTP-only operation
remains possible without making persistent browser support mandatory.

### L3 — Validate generated harness fidelity and real-path proof (P1)

**Depends on:** L2; no probabilistic/model-checking engine required.
**Touchpoints:** `leadpipe.py`, existing validators, flags/findings and run artifacts.

- [ ] ENV-13: Record internal calls, stubs, instrumented paths and synthetic-state
  assumptions; distinguish fast exploratory results from confirmed app behaviour.
- [ ] ENV-14: Map a candidate to the real entry point with justified preconditions,
  the actual assessed identity, applicable controls and independent effect observation.
- [ ] ENV-15: Add positive, repaired, normal-use, middleware-bypass-only and invalid
  internal-object cases; report harness-only and unknown-fidelity outcomes separately.
- [ ] ENV-16: Compare simplified versus full-path observations and preserve all
  failed replays, unsupported assumptions and claim limitations in evidence.

**Acceptance:** a genuine application violation reproduces without removing its
security boundary; an artificial harness failure is not promoted to that claim.
Coverage alone and a broken always-deny repair cannot satisfy acceptance.

### L4 — Test supported configuration and upgrade scenarios (P2)

**Depends on:** L3 and owner-approved configuration/migration authority.
**Touchpoints:** environment manifests, existing config hints and application fixtures.

- [ ] ENV-17: Define a small supported factor/constraint model with policy provenance,
  invalid-combination handling and observable effective-setting assertions.
- [ ] ENV-18: Select bounded interaction tests and report their coverage/limitations;
  keep combinatorial tools optional and count all preparation overhead.
- [ ] ENV-19: Add a fresh-install versus one supported-upgrade comparison for a
  specific security rule, preserving intentional product differences.
- [ ] ENV-20: Test unapplied settings, incompatible combinations, failed migrations,
  propagation windows and ambiguous resets without automatic repeated mutations.

**Acceptance:** configuration-dependent claims name conditions that were actually
active and supported. A migration result describes the tested history, not every
upgrade path; unknown or intentionally different behaviour is not a false finding.

### L5 — Export portable proofs and measure preparation value (P2)

**Depends on:** L3; include L4 scenarios only when implemented.
**Touchpoints:** existing evidence/report exports, independent runner and evaluator.

- [ ] ENV-21: Export a redacted synthetic capsule with pinned recipe, environment,
  subject capabilities, normal-flow evidence, proof, limitations and cleanup.
- [ ] ENV-22: Import/replay with a separate authorised runner without chat history;
  test secret leakage, tampered manifests, missing prerequisites and stale permission.
- [ ] ENV-23: Run equal-input end-to-end and equal-ready-environment comparisons;
  include setup failures, manual effort, fidelity defects and independently verified causes.
- [ ] ENV-24: Publish counts, costs, uncertainty and regressions; promote or roll back
  each adapter based on predeclared fidelity/safety/discovery gates, not harness count.

**Acceptance:** independent reproduction succeeds for applicable cases without
hidden setup privileges. Savings in preparation are reported separately from new
bug-finding power. Non-reproduced cases and no-improvement outcomes remain visible.

## Evaluation and release gates

Use unfamiliar applications within the declared first stack, not just renamed
routes in one generated fixture. Freeze versions, normal-use information, owner
policy, credentials, model/provider, prompts, budgets and allowed capabilities.
Keep expected defects and safe-mode switches evaluator-only, including source and
hook names where those would reveal the answer. Synthetic fixtures, historical
rediscoveries and newly validated real findings are separate result categories.

Compare from identical starting materials, counting all preparation and permitted
human help. Also compare in equally ready environments to isolate any change in
search quality. A baseline that cannot prepare a project must remain in end-to-end
denominators; report its limitation rather than silently dropping that project.
Repeated-trial counts and uncertainty must match the declared question and variability.
No universal number of trials or performance gain is asserted by this proposal.

| Metric | Required interpretation |
| --- | --- |
| Preparation success | Projects reaching a verified normal flow divided by all admitted projects; keep unsupported/failed cases visible. |
| Setup effort | Wall time, compute/model use, dependency acquisition, resets and permitted human interventions before a meaningful check. |
| Fidelity | Candidates confirmed through a real boundary, harness-caused failures, unknown fidelity and assumptions disproved by controls. |
| Discovery | Independently adjudicated new/lost causes and false claims; seeded-suite recall versus real-target yield, with limitations. |
| Portability | Independent fresh-environment reproduction and failure reasons, not merely successful re-import of a JSON file. |
| Safety | Out-of-scope sends, privilege/credential leakage, active resources after cancellation, unapproved changes and incomplete cleanup. |

**Software gate:** deterministic admission, isolation, lifecycle, compatibility,
normal-flow and fidelity regression fixtures pass. A tested control cannot be
replaced by a mock that assumes the property being investigated. Unknown adapter
capabilities fail closed; historical receipts remain readable and are not replayed.

**Product gate:** meet predeclared preparation, fidelity, precision/replay and total
resource margins in repeated held-out comparisons. Publish unsuccessful projects
and harms to existing workflows. A rise in container count, generated code or code
coverage alone is not a discovery improvement. Changes to the stack, runner or
support policy require revalidation, not automatic transfer of old guarantees.

## First implementation slice

Start with ENV-01–ENV-04 and isolated reproductions of the audited runner/guard
concerns. Then ENV-05–ENV-08 establish one safe execution path. Do not begin by
letting an agent run arbitrary repository commands through the current sandbox.

Prepare one normal app flow, prove a single existing detector's meaningful result
through the real entry point, and reject one deliberately incorrect harness.
Only after that expand to configuration combinations, upgrades and additional
stacks. Every code PR must state reused components, satisfied gates, migrations,
actual tests and measured results. This PR changes only documentation and performs
no application setup, target testing or runtime/dependency modification.

## Design references

Primary references checked on 2026-10-15. They motivate techniques, not MoonMCP's
own performance. Check APIs, licensing and assumptions before choosing an adapter.

- **U1 — [Lessons from Mitigating False Positives in Google's OSS-Fuzz-Gen](https://research.google/pubs/lessons-from-mitigating-false-positives-in-googles-oss-fuzz-gen/).**
  Studies generated-driver constraints and context-aware validation against
  realistic entry points. Adapting that discipline to authenticated web workflows
  needs independent policy, fixture and fidelity evidence.
- **U2 — [NIST ACTS: downloadable tools](https://csrc.nist.gov/projects/automated-combinatorial-testing-for-software/downloadable-tools).**
  Documents constrained and variable-strength interaction coverage. Such coverage
  is a selection technique, not proof of security for untested combinations.
