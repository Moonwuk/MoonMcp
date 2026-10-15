# Capability audit and roadmap reconciliation

**Reviewed:** 2026-10-15. **Code baseline:**
[`40ef2bc`](https://github.com/Moonwuk/MoonMcp/commit/40ef2bc662337c32707372d3e2475404f3019879).
**Purpose:** distinguish existing MoonMCP code from improvements proposed in
PRs #15–#19 and the [research-environment plan](RESEARCH_ENVIRONMENT_ROADMAP.md).
This is a source-based audit, not a release certification or penetration test.

## Executive finding

MoonMCP already contains much more than a collection of reconnaissance wrappers.
There are durable runs and evidence, hypothesis review rules, a tool-policy
registry, callback-based agents, cross-target lessons, BOLA chains, browser
interaction, request replay primitives, parser/race/second-order probes, local
SAST, patch/variant research helpers and a Docker execution class.

Several earlier recommendations were too broad when framed as adding these
capabilities from scratch. The useful remaining work is generally **stronger
semantics, safer execution, integration and independently checked proof**, not
another implementation with a new name. The source distinctions below supersede
blanket absence claims; they do not mark entire roadmap milestones complete.

### These primitives predate the roadmap PRs

The Git trees for the initial review commit `27702d3` and current `40ef2bc` have
identical entries for the following paths:

| Path | Identical Git object at both commits |
| --- | --- |
| `moonmcp/` | `8503c6a48529bec01fdc5b9e0a2c523e41595fe1` |
| `tests/` | `d2271b72057117e148e4ffca2df7aeb5b00fc23b` |
| `pyproject.toml` | `f370f26e71a13b4735ed1da8f677a64a3aa5a8ea` |

Evidence: [initial tree][tree-old] and [reviewed tree][tree-current]. This establishes
unchanged content in those paths, not identical content across the whole repository.
Their presence is a correction to the earlier inventory, not an implementation
result produced by merging the new Markdown roadmaps.

At this review, the first four discovery documents are present in `main`.
[PR #19][pr19] is open; its probabilistic plan is compared using its
[pinned proposed content][probabilistic], not assumed to exist in `main`.

## Method and limits

Read the live branch/tree metadata, registry declarations, relevant implementation
bodies, existing documentation and selected recovery/CI test definitions through
the GitHub connector. This was a targeted architectural review, not a line-by-line
review of every module. File links below pin the examined version.

**Source-confirmed** means implementation was inspected. **Partial** means an
existing primitive covers only part of a proposed end-to-end capability.
**Declared** means registration/reference was observed but the entire execution
path was not inspected. **Not evidenced** means the requested capability was not
established in the inspected implementation; it is not a proof of repository-wide
absence. Dependency-installed, callable, correctly guarded, well-tested and useful
on a real target are separate properties.

No application test suite, installed-tool enumeration, Docker/browser runtime,
external scanner, target experiment or discovery benchmark was executed for this
audit. A local clone attempt failed because the runtime could not resolve GitHub;
connector reads were used instead. GitHub code search returned incomplete results,
so empty search results were not used as evidence of absence. Test source is not a
passing test result. Local validation of this PR's Markdown is reported separately.

## Existing capabilities and their actual boundaries

| Area | What exists in inspected source | What should not be inferred |
| --- | --- | --- |
| Registry and navigation | `ToolPolicy`, central accounting metadata, discovery/description declarations, and extracted registration families. Unknown policies default to unmetered. [Registry][registry], [families][families]. | Every tool is metered, every family migrated, or all runtime dependencies are installed. Do not create a competing registry. |
| Managed execution | `ExecutionScope.before_request` reserves each supported HTTP send; run target and scope/auth context are checked. Results can be chunked into hashed artifacts. [Executor][execution]. | Direct calls, Docker, browser and raw protocols automatically share that budget. A hashed artifact proves integrity, not the correctness of a claim. |
| Durable coordination | Recovery tests exercise competing claims, ownership tokens, lease expiry, idempotent receipts, unknown outcomes, atomic budgets and retained limitations. [Recovery tests][recovery]. | Those tests were run here, or lease-based task coordination is a complete native LLM research loop. |
| Flags and hypotheses | Review requires a completed check for support/refutation; stale support and unresolved contradictions block support. Source groups are declared provenance, not independent evidence. [Flag store][flags]. | Supporting a hypothesis automatically creates a confirmed finding or validates evidence meaning. |
| Memory and lessons | Persistent memory search, typed graph links, revision views, briefs and cross-target `memory_lesson` storage/recall. [Memory tools][memory]. | A `curated` label means independent review occurred. `memory_lesson(action="add")` itself writes curated/manual metadata; a governed method-promotion lifecycle is additional work. |
| Agents | `BaseAgent`, `ReconAgent`, `ExploitAgent` and graph/status/memory infrastructure exist. Recon/exploit execution uses injected action/probe callbacks. [Agents][agents]. | Role names imply automatic probe discovery, provider-neutral model reasoning or self-directed hypothesis testing. Reuse this scaffolding and run state. |
| Authentication and BOLA | Engagement headers/cookies, explicit user-B/anonymous comparisons, adjacent references and owner-response-to-next-request chains. `ObjectRef` records numeric/UUID type and exact URL location. [Auth][auth], [BOLA][authz]. | No object model exists at all. The missing layer is semantic owner/tenant/resource typing, liveness and policy; current body comparison uses the first 4 KiB and returns review leads. |
| Browser interaction | Optional Playwright rendering/evaluation and action sequences; `interact` returns cookies and local storage, then closes its browser. [Browser][browser]. | Durable named sessions, complete network recipes, actual-send budgeting or uniform fail-closed routing across all browser functions. See hardening priorities. |
| HTTP replay and proxy primitives | Raw/structured request handling, bounded history and native Burp-style workflow. `ProxyStore` can prepare modified raw requests for a later repeater call. [Interception][intercept], [adapted tools][adapted]. | A full live MITM/Burp integration, lossless durable request corpus or dependency-aware replay. History is in-memory with body previews; preparing replay text is not sending it. |
| Business logic and races | Parameter/mass-assignment checks, negative controls and parallel race requests. State-changing mass-assignment/race probes default to dry-run and warn about no rollback. [Logic][logic]. | A deterministic internal scheduler, independent final-state proof, automatic cleanup or a general fault-injection environment. Multiple 2xx responses are review evidence. |
| Workflow and stored effects | Supplied-step skipping and second-order write/read checks with tagged/control observations. [Workflow][workflow], [second-order][secondorder]. | General state-machine synthesis, automatic discovery of business intent or complete outcome handling for every subcheck. |
| Parser differentials | Canonical/quirk/control request families and analysers distinguish decode, tolerance and informational precedence signals. [Parser differential][parserdiff]. | No differential testing exists. The proposed extension is actual cross-component meaning/authority evidence and demonstrated policy impact, not another basic parser probe. |
| Source analysis | `sast_scan` is backed by local regex/pattern analysis for several languages and vulnerability classes, with file/line evidence. [SAST][sast]. | AST/data-flow completeness, branch feedback or a build-bound connection between a static lead and the executed application path. |
| Patch and variant research | `cve_patch_diff` obtains advisory data and can read the first referenced PR diff. `variant_search` maps keywords/CWEs/root-cause categories to probes, questions and knowledge sources. [Research helpers][zeroday]. | Semantic whole-repository variant detection or automatic proof. `poc_pipeline` is returned data; its reproduction-labelled step points to `add_finding`, not an independently executed replay. |
| API inventory | JSON/optional YAML OpenAPI parsing extracts operations, parameters, security declarations and body types. [OpenAPI][openapi]. | A working application fixture, generated valid stateful requests, or permission to test every server mentioned in a spec. |
| Docker execution | Native `DockerSandbox.start/exec/stop/status` with CPU/memory limits and the `sandbox_exec` registry entry. [Docker implementation][adapted], [registry][registry]. | No sandbox exists. Also do not infer rootless/minimum-privilege execution, network-enforced scope, guaranteed cancellation or automatic application setup. |
| Reporting and calibration | Enhanced SARIF/Markdown support, deterministic deduplication and findings/metrics/export declarations. [Adapted reporting][adapted], [registry][registry]. | Semantic proof of a common root cause, a portable environment capsule or measured discovery precision/recall. |
| Timing and configuration-related tools | `timing_diff`, `analyze_config`, `extract_api_schemas` and other entries are declared in the registry. [Registry][registry]. Their complete paths were not audited here. | These categories are absent; equally, a name establishes neither a statistically valid campaign ledger nor generation of supported deployment combinations. |
| Knowledge and local pipeline | Searchable reference playbooks and local Hermes queue/target/dataset readers. [Knowledge][knowledge], [pipeline][pipeline]. | Every optional dataset is present or reference text is an executable research method. A local task queue is not an environment builder. |
| Evaluation and CI | `bench.py` runs real tools against a socket-denied in-process transport. CI config includes lint, type checks, coverage and installed-wheel MCP smoke. [Bench][bench], [CI][ci]. | The benchmark measures LLM success or token cost, or CI passed in this audit. Existing fixture infrastructure should be extended, not discarded. |

The catalog also declares a broad reconnaissance and security surface: DNS/HTTP/TLS,
crawling/JavaScript, OSINT/CVE, GraphQL, OAuth/JWT, cache, injection and external CLI
families. Those entries establish breadth, not equal implementation depth or a
comparative effectiveness result. No current tool count is asserted without live
profile/dependency-aware enumeration. See [registry][registry] and [server][server].

## Reconciliation with every earlier discovery plan

These are implementation deltas, not rewritten historical checkboxes. Reuse the
existing source in the table above and require the original acceptance evidence
before closing a milestone. Optional research tracks are not sequential prerequisites.

| Plan / workstream | Existing foothold | Remaining delta / recommended action |
| --- | --- | --- |
| [Foundation][foundation] M0, M5 evaluation | Offline `bench.Harness`, in-process transport, CI/recovery tests. | Add independently labelled vulnerable/patched/safe discovery fixtures and matched agent trials; retain existing navigation benchmarks. |
| Foundation M1 proof | `confirm.evaluate`, `leadpipe.confirmation_plan`, reviewed hypotheses. [Confirmation][confirm], [lead routes][leadpipe]. | Implement class-specific evidence validators and explicit incomplete subchecks; do not replace one score with another unsupported confidence number. |
| Foundation M2 identities/BOLA | Current engagement auth, B headers, syntactic `ObjectRef`, multi-step BOLA. | Add named live sessions, semantic ownership/tenant policy and independent protected-object observation. Extend the current module. |
| Foundation M3 action corpus | Browser sequences, raw repeater/history, proxy modification and OpenAPI inventory. | Add durable bounded recipes, secret references, dependency refresh and actual-send metering; not browser automation from zero. |
| Foundation M4 workflow | Step-skipping and second-order templates, run recovery. | Establish real state transitions, expected rules, safe preparation and independent re-observation. |
| [Advanced][advanced] A1 relations | Typed memory graph and flag support/contradiction links. | Add evidenced representation/policy relationships and executable property-specific controls; avoid a second graph store. |
| Advanced A2 source/runtime | Local SAST, JS/OpenAPI inventory, patch excerpts and browser event metadata. | Build/deployment-bound route/data-flow/runtime feedback and explicit missing-telemetry limits. Existing telemetry labels do not prove target execution tracing. |
| Advanced A3 experiments | Fixed probe chains, supplied browser actions, run dependencies and receipts. | Typed bounded composition, precondition-valid state exploration and claim-preserving minimisation. Reuse executor; do not route around unsupported accounting. |
| Advanced A4 variants/changes | `variant_search`, `cve_patch_diff`, graph `caused_by`, surface-diff declarations. | Real candidate locations/relationships, independent variant proof and change-impact regression selection. Preserve helper names and distinguish returned plans from execution. |
| Advanced A5 methods | Cross-target lessons, trust/provenance, reference playbooks. | Independent promotion review, applicability tests, safe counterexamples, expiry/revocation and controlled cross-project transfer. |
| [Experimental][experimental] E0, E6 | Offline fixtures, recording/labels and static FP tips in research helpers. | Evaluator-owned miss diagnosis, held-out mutations and measured strategy selection; not self-grading against hardcoded tips. |
| Experimental E1–E2 ordering/faults | Parallel race probe, task leases, existing Docker lifecycle. | Internal barriers, feasible schedule replay, approved faults, watchdogs and proved recovery; parallel sends are not this scheduler. |
| Experimental E3 interpretation | `parserdiff`, raw HTTP behaviour and related probe declarations. | Evidence of actual check/use meanings through a permitted chain and a concrete security effect. Reuse request/control builders. |
| Experimental E4 directed search | Local SAST and normal external-tool integration points. | No bounded constraint/coverage-guided execution adapter was established by this review. Add one only for an observed reachability bottleneck. |
| Experimental E5 composition | Existing request chains, graphs, observed tags and root-cause references. | Validate joint feasibility across subjects/builds/states and final effects; independently controlled causal comparisons remain new work. |
| [Relational][relational] R0–R1 pairs | A/B/anonymous comparisons and deterministic controls in individual probes. | Two-world manifests, secret-only/public-state equivalence, privileged setup versus observer separation, integrity rules and fresh-pair replay. |
| Relational R2 rules/oracles | Confirmation criteria, reference policy content and structured hypotheses. | Reviewed requirement-to-rule translation, versioned approval and independent oracle validation; prose is not an executable policy compiler. |
| Relational R3 flows | Typed relations, code/metadata leads and service context. | Confidentiality/integrity semantics and current-deployment-bound information/authority paths validated by effects. |
| Relational R4–R5 models/evaluation | Supplied sequences, persistence and baseline harness. | Small checked behavioural models, concrete replay/refinement and independent relational discovery evaluation were not established. |
| [Probabilistic proposal][probabilistic] P0–P3 | Timing/differential signal interfaces, sampled probe responses, recording. | Fixed-protocol fresh-data inference, valid episode units, transcript-level proofs, blind observers and independent replication. Do not describe timing as a wholly absent category. |
| Probabilistic P4–P6 | Durable runs/budgets and benchmark infrastructure. | Statistical testing-error allocation is not request accounting. No campaign ledger, supported sequential guarantee or calibrated optional AI-app/timing auditor was established. |
| [Environment proposal](RESEARCH_ENVIRONMENT_ROADMAP.md) | DockerSandbox, SAST/OpenAPI hints, browser/repeater primitives, agent/run scaffolding and test harnesses. | Harden/adapt the runner, construct normal app state, check harness fidelity, verify supported configurations and package independent reproduction. Not a new generic shell tool. |

## Source-level hardening priorities before more autonomy

The following are concrete review concerns, not demonstrated attacks on a deployed
server. This documentation PR neither fixes nor actively reproduces them.

**1. Browser guard consistency.** In [browser.py][browser], `_install_scope_guard`
can fall back to `route.continue_()` after a guard operation fails, and registration
failure is swallowed. `interact()` creates its own context but does not install
that helper; its explicit `goto` action checks do not themselves cover every
browser-generated navigation/subresource. Add isolated tests for installation and
abort failures, redirects, clicks, subresources and credential destinations before
reusing either path as a trusted autonomous transport.

**2. Sandbox trust boundary.** [DockerSandbox][adapted] defaults to bridge networking,
additional network capabilities and a host-gateway entry. Its optional scope test
matches literal HTTP(S) hosts in the command string; that is not an egress control.
It uses an unpinned image tag and a fixed shell command. Image/shell compatibility,
container-side process termination after timeout and checked stop/remove outcomes
need explicit tests. The process-local container ID is not a durable environment
lease. Do not equate CPU/memory limits with a complete sandbox policy.

**3. Managed coverage is deliberately partial.** [Registry][registry] leaves many
active probes and non-HTTP transports unmetered; the managed [executor][execution]
restricts supported dispatch accordingly. Preserve that boundary. Add accounting
at actual execution/send points before integration, never make a tool appear
managed simply by relabelling its policy or counting one wrapper invocation.

**4. Outcome and evidence semantics.** [Workflow][workflow] returns false for a
missing status and can aggregate this to `no_step_skip`. [BOLA][authz] similarly
needs incomplete subcheck accounting instead of relying on an empty finding list.
[Confirmation][confirm] can assign `confirmed` from generic OAST or signature-plus-
reflection signals. Preserve legacy compatibility but use explicit class/claim
proof in new verified-report paths. A callback or HTTP 200 does not establish
arbitrary execution, ownership or a business effect by itself.

**5. Lessons require governance, not just a trust string.** [Memory tools][memory]
allow the lesson-add path to label content curated/manual. Add explicit provenance,
review and transfer rules before using such records as independently validated
methods. Do not automatically promote agent-authored conclusions through this path.

These priorities justify targeted code/reproduction PRs. They do not justify
silently rewriting prior findings or claiming the entire project is unsafe.

## Revised implementation order

First, reconcile existing APIs and reproduce the highest-risk boundary/outcome
concerns on isolated fixtures. Then deliver one semantic BOLA proof path using the
existing auth/probe/run/flag stack. In parallel, harden the existing sandbox and
prepare one faithful application environment; preserve an HTTP-only route when
browser support is unavailable or not yet admissible.

Only then choose optional state, model, statistical or source-guided engines from
measured discovery misses. The environment track does not depend on completing
all five research roadmaps. An experiment that saves preparation effort is useful,
but must be reported separately from an improved vulnerability-discovery strategy.

Before each implementation PR, re-read the current code and attach acceptance
evidence. For each inherited task choose: reuse unchanged; extend with a stated
delta; harden/repair; or defer pending evidence. Do not close a task just because a
similarly named function, prompt, test file or Markdown proposal exists.

## Evidence references

All implementation references are pinned to the reviewed commit. The audit does
not quote dependency availability, test counts, coverage results or scanner efficacy
that were not measured here.

[tree-old]: https://api.github.com/repos/Moonwuk/MoonMcp/git/trees/27702d3037b68dbe31b960ea69fb20ba428469f2
[tree-current]: https://api.github.com/repos/Moonwuk/MoonMcp/git/trees/40ef2bc662337c32707372d3e2475404f3019879
[pr19]: https://github.com/Moonwuk/MoonMcp/pull/19
[probabilistic]: https://github.com/Moonwuk/MoonMcp/blob/4566c6fa38c13cf4bc7646ac5bc50d8572017d17/docs/PROBABILISTIC_DISCOVERY_ROADMAP.md
[foundation]: VULNERABILITY_DISCOVERY_ROADMAP.md
[advanced]: ADVANCED_DISCOVERY_ROADMAP.md
[experimental]: EXPERIMENTAL_DISCOVERY_ROADMAP.md
[relational]: RELATIONAL_DISCOVERY_ROADMAP.md
[registry]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/registry.py
[families]: https://github.com/Moonwuk/MoonMcp/tree/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/families
[server]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/server.py
[execution]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/execution.py
[recovery]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/tests/test_run_recovery.py
[flags]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/flags.py
[memory]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/families/memory.py
[agents]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/orchestration/agents.py
[auth]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/auth.py
[authz]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/web/authz.py
[browser]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/web/browser.py
[intercept]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/intercept.py
[adapted]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/strix_adapted.py
[logic]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/web/logic.py
[workflow]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/web/workflow.py
[secondorder]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/web/secondorder.py
[parserdiff]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/web/parserdiff.py
[sast]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/recon/sast.py
[zeroday]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/intel/zeroday.py
[openapi]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/recon/openapi.py
[confirm]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/confirm.py
[leadpipe]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/leadpipe.py
[knowledge]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/families/knowledge.py
[pipeline]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/pipeline.py
[bench]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/moonmcp/bench.py
[ci]: https://github.com/Moonwuk/MoonMcp/blob/40ef2bc662337c32707372d3e2475404f3019879/.github/workflows/ci.yml
