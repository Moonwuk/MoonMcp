# Implementation priorities after capability reconciliation

**Original planning update:** 2026-10-15. **Historical baseline:**
[`a6023a4`](https://github.com/Moonwuk/MoonMcp/commit/a6023a4b37e5a6fe194db5275bc9a72faa76e032).
**Status:** delivery requirements with a historical planning baseline.

**Current reconciliation (2026-10-21):**
[Source-based roadmap status](ROADMAP_STATUS_2026-10-21.md) distinguishes implemented,
partial and remaining work. The original planning baseline below is historical.
The private-read proof, managed execution, two trusted application recipes and
independent replay are now implemented within their documented limits. This delivery
adds deterministic comparison and repairs selected browser, external execution,
persistence and data-validation gaps; fixed-model trials and arbitrary-project
preparation remain outstanding.

**Harness direction (2026-10-21):** the
[research harness architecture and roadmap](RESEARCH_HARNESS_ROADMAP.md) maps
existing capabilities to an external-agent task-to-proof pilot and measured
continuation, session and tool-interface improvements. It extends IP-01/IP-05/IP-08;
it does not restart delivered work, supersede reproduced guard/outcome repairs or
require an internal LLM coordinator. The first code deliverable is a reproducible
external-agent baseline on the supported HTTP path; choose further changes from
observed failures.

## Decision

Deliver one trustworthy, measured HTTP BOLA investigation using existing components
before expanding the research architecture. Fix reproduced boundary/outcome defects;
harden optional browser/container execution in parallel before relying on it.

> Known test identities and policy → observed object → admitted verification
> → concrete protected-object evidence → preserved limitations → independent replay.

This index sets the near-term order for the discovery/autonomy proposals. Their
ordinal stage names and local P0 labels are not a global queue. Detailed safety,
proof, compatibility and evaluation requirements remain binding when a track is
selected; this index does not weaken them or authorise target actions. Unrelated
product work in the [layer backlogs](../roadmaps/README.md) is not cancelled.

Read the [capability audit](CAPABILITY_AUDIT_2026-10-15.md) for pinned implementation
evidence and its limits. At the original planning baseline, the merged tree had `moonmcp/` object
`8503c6a48529bec01fdc5b9e0a2c523e41595fe1`: merging the planning PRs did not implement
their recommendations. Source presence, installed availability, passing regression
tests and measured discovery effectiveness are different claims.

## Keep the plans, select the work

| Document | Disposition | When its larger scope becomes active |
| --- | --- | --- |
| [Capability audit](CAPABILITY_AUDIT_2026-10-15.md) | Use now as a dated evidence map; recheck code before each change. | It is not a live certification or a completion checklist. |
| [Research harness](RESEARCH_HARNESS_ROADMAP.md) | Reuse runs/evidence/verification; measure an external agent from initial task to independently reviewed result. | Select continuation, session or interface changes from measured failures. Internal coordination is optional. |
| [Evidence-driven discovery](VULNERABILITY_DISCOVERY_ROADMAP.md) | Select baseline, honest outcomes and the semantic BOLA proof path now. | Expand beyond that path after the independent fixture gate. |
| [Research environments](RESEARCH_ENVIRONMENT_ROADMAP.md) | Select runner hardening in parallel, then one faithful normal app flow. | More stacks, configuration matrices and upgrades need measured preparation gaps. |
| [Advanced discovery](ADVANCED_DISCOVERY_ROADMAP.md) | Reuse only the relations/recipe requirements needed by the selected path. | New state-search, source/runtime and method-transfer engines need an evidenced miss and a bounded evaluation. |
| [Experimental discovery](EXPERIMENTAL_DISCOVERY_ROADMAP.md) | Retain as conditional research; do not rebuild existing race/parser probes. | Controlled ordering/faults or directed search need a demonstrated triggering/reachability bottleneck and the relevant lab gates. |
| [Relational discovery](RELATIONAL_DISCOVERY_ROADMAP.md) | Defer paired-world, policy-compilation and model-checking work. | An approved rule and a reproducible indirect-disclosure/integrity gap justify a selected experiment. |
| [Probabilistic discovery](PROBABILISTIC_DISCOVERY_ROADMAP.md) | Retain as deferred research, not the next release commitment. | A stochastic or cumulative signal needs a supported protocol, independent calibration and durable statistical error accounting. |

No plan is deleted merely because its primitive already exists. Reconcile each
inherited task as **reuse**, **extend**, **harden/repair** or **defer**; do not mark a
whole milestone done from a similar function name. Keep original task identifiers
and link implementation evidence back to them rather than duplicating their work.
An agent-created `curated` lesson is not independent evidence for activating a track.

The artifact proposal in [PR #25](https://github.com/Moonwuk/MoonMcp/pull/25)
remains a separate input-adapter track. Its offline OCI slice can be selected for
a concrete evidence gap without completing general autonomy or every harness
package; remote and optional adapters retain their own gates. Its documentation
does not mark those integrations implemented.

## Near-term implementation bundles

The original planning PR started none of these bundles. Several bounded portions
have since shipped; consult the current status map before selecting more work.
The acceptance criteria below remain requirements, not blanket completion claims.
The critical HTTP path is IP-01 → IP-03 → IP-04 → IP-05. IP-02 and IP-06 are parallel
hardening work, not prerequisites for a fixture that does not use those transports.
IP-07 requires the selected environment/transport gates. IP-08 starts baseline
measurement with IP-01 and provides the final integration gate.

### IP-01 — Reproduce gaps and freeze a small baseline

Reuse `bench.py`, existing fixtures and the registry. Record the revision, selected
profile, installed dependencies and actual accounting coverage; unavailable tools
must remain visible. Use synthetic users in two tenants, known private/shared/public
objects, one normal flow and independently labelled vulnerable/patched variants.
Add missing-status, expired-session and long-body cases before changing detection.

**Acceptance:** reproduce each claimed defect in isolation or document why it is
unconfirmed; keep baseline misses and false claims. No live target is needed.
**Maps to:** foundation VD-01–VD-03; environment ENV-01–ENV-04.

### IP-02 — Make browser guards fail closed where browser work is used

Extend `web/browser.py` and its existing tests. Reproduce guard installation,
abort/continuation and `interact` coverage concerns from the audit. Cover redirects,
clicks, subresources and credential destinations, not just explicit `goto` calls.
An unguarded context must not send requests after an admission/guard failure.

**Acceptance:** isolated browser tests observe no forbidden sends or credential
forwarding; allowed normal navigation still works. Do not claim managed browser
support until actual-send accounting and cancellation pass their separate gates.
**Maps to:** audit browser priority; environment ENV-08; foundation M3 transport gates.

### IP-03 — Preserve incomplete outcomes in composite checks

Extend `web/workflow.py`, `web/authz.py` and their adapters using the existing
[outcome contract](TOOL_OUTCOMES.md). Preserve per-subcheck status and distinguish a
completed negative from missing data, budget stops and unknown effects. A completed
request is not a verified claim, and an empty finding list is not full coverage.

**Acceptance:** transport failures cannot aggregate into an unqualified reassuring
negative. Existing receipts remain readable; changed payload semantics have an
explicit versioned compatibility path. Do not silently rewrite historical results.
**Maps to:** foundation VD-04/VD-06; audit outcome priority.

### IP-04 — Prove one semantic BOLA claim

Extend existing `ObjectRef`, authentication and BOLA probes rather than replacing
them. Add only the named, isolated live subjects, typed resource ownership/tenant
facts and declared policy needed for a private-object read. Verify the actual
object/protected fields beyond a generic status or the first 4 KiB of a response.
Keep `confirm.py` signals as leads; a new verified-report path needs class-specific
proof, controls, missing-evidence reasons and versioned provenance.

**Acceptance:** prove the vulnerable private read; reject patched, public and
intentionally shared cases. Unknown policy, stale identity, wrong object type or
missing decisive bytes prevents promotion without discarding the useful lead.
**Maps to:** foundation VD-04/VD-05/VD-07/VD-08; web-auth WA12/WA13/WA19.

### IP-05 — Connect that proof to managed execution and evidence

Execute a supported `leadpipe` route through existing registry/run APIs; an offline
plan is not an executed check. Reserve every actual send, including identity and
control requests, and retain proof/limitations in existing artifacts and stores.
Test cancellation, changed policy/session context, ownership leases and recovery.
Do not relabel an unmetered tool to make this integration appear supported.

**Acceptance:** a fresh authorised fixture reproduces the narrow finding with
redacted evidence. Unknown interrupted operations require reconciliation, not
implicit replay. Direct-call and unsupported-transport limits stay explicit.
**Maps to:** foundation VD-09; existing execution/recovery contracts.

### IP-06 — Harden the existing container runner before app preparation

Reuse `DockerSandbox` behind an opt-in, compatible adapter. Pin approved inputs,
reduce privileges and enforce actual egress; command-string URL matching is not a
network boundary. Bound child resources/output, persist resource IDs and leases,
reserve cleanup capacity and verify in-container termination after cancellation.

**Acceptance:** forbidden execution/traffic is blocked at its real boundary.
Worker loss yields verified cleanup or explicit quarantine under approved policy.
No arbitrary repository commands, production secrets or generated app setup are
admitted through an unverified runner. Unsupported managed execution stays blocked.
**Maps to:** environment ENV-05–ENV-08; audit sandbox/accounting priorities.

### IP-07 — Prepare one real application and retain a portable proof

After IP-05/IP-06 and applicable transport gates, choose one approved stack. Use
existing HTTP/browser primitives to prepare synthetic objects and establish normal
use through the real entry point. Separate controller privileges from the assessed
user. Independently observe readiness/effects; record stubs and instrumentation.
Reject a finding created only by bypassing middleware or fabricating unreachable
internal state. Package the synthetic recipe and test it with a separate runner.

**Acceptance:** normal use and the verified effect reproduce without hidden manual
steps; a deliberately invalid harness is rejected. Missing dependencies, failed
cleanup and non-reproduced effects remain visible. Saving proof grants no replay
permission on a different target. HTTP-only operation does not require Playwright.
**Maps to:** environment ENV-09–ENV-16 and selected ENV-21/ENV-22.

### IP-08 — Publish the result before promoting a new research engine

Reuse the independent baseline from IP-01. Compare existing versus integrated
workflows with fixed identities, policy, model/input access and budgets. Evaluate
application preparation separately: both equal starting materials and equally ready
environments matter. Count unique adjudicated causes, false claims, unfinished
checks, fresh replays, manual preparation and total cost; do not count tool calls
or generated harnesses as discoveries. Include safe cases and unseen fixture variants.

**Acceptance:** publish gains and regressions under predeclared criteria, including
no-gain results. Scope/credential/recovery failures are blockers, not score offsets.
Broader engines require a recorded miss, a responsible owner, bounded experiment
and their own acceptance evidence. No mandatory many-agent, graph-database, solver
or statistical dependency is introduced by the selected BOLA path.
**Maps to:** foundation evaluation/M5; environment ENV-23/ENV-24.

## Shared proof and release gate

These are acceptance requirements. Consult the current status map and linked
regression tests for the portions implemented; this table alone reports no test result.

| Case | Required interpretation |
| --- | --- |
| Another live test subject receives a known private object contrary to policy. | Verified BOLA only with identity/ownership evidence, controls and a concrete protected-object effect. |
| Public/shared object or a generic HTTP 200 application shell. | No verified private-object violation merely from similarity/status. |
| Expired session, wrong binding, timeout, truncated decisive evidence. | Explicit incomplete/inconclusive result, not a clean negative. |
| Out-of-scope destination, credentials for another audience, exhausted budget. | Block before the affected send; no alternate unguarded transport fallback. |
| Interrupted operation with unknown effect. | Preserve uncertainty and require evidence-backed reconciliation before any authorised retry. |
| Candidate works only in a harness that removed a material check. | Harness-specific result, not a proven violation of the normal application. |

Use the existing `moonmcp.result` contract, request accounting and proof stores.
Approvals remain scoped; setup authority is not user authority. Legacy `confirmed`
labels are not retroactively verified. Preserve coverage gaps and never treat a
merged document, green unrelated test or unavailable automated reviewer as evidence
that these requirements have been met.

## PR disposition and document history

At this baseline, #15–#18 had already been merged. [#20](https://github.com/Moonwuk/MoonMcp/pull/20)
was then merged for its capability corrections and reuse-first environment plan;
[#19](https://github.com/Moonwuk/MoonMcp/pull/19) was retained and merged as conditional
statistical research. Neither was a duplicate requiring closure without merge.
The audit's older statement that #19 was open is a dated snapshot, not current PR
status. Earlier design text and task IDs remain available; this index changes the
selection/order of implementation work, not their recorded history or completion.

The bounded IP-04/IP-05 proof path and trusted IP-06/IP-07 recipes now exist.
IP-08 has a deterministic comparison with held-out synthetic controls and fresh
replay; it does not establish model-driven or real-project discovery gains.
Next work must address a demonstrated remaining limitation, such as named-session
lifecycle, supported schema coverage or faithful project preparation. Update only
acceptance items established by actual code, tests and review.

The original consolidation was documentation only. Subsequent code deliveries are
tracked in the current reconciliation. A merged document or passing unrelated test
does not establish implementation completion or measured discovery improvement.
