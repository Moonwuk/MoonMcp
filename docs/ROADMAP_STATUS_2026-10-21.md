# Roadmap implementation status — 2026-10-21

**Audit baseline:** [caad7c9](https://github.com/Moonwuk/MoonMcp/commit/caad7c9cf135318b3a5155b12facfb190a958dde).
**Delivery scope:** selected reliability fixes and deterministic evaluation,
tracked in [PR #26](https://github.com/Moonwuk/MoonMcp/pull/26). The source and
acceptance tables below distinguish implemented portions from remaining work.
**Validation evidence:** the exact assembled head and CI results are recorded in
[PR #26](https://github.com/Moonwuk/MoonMcp/pull/26). Consult its checks before merge.
Checks apply to their recorded source revision; later changes require fresh validation.

The review compares the implementation and regression tests with the
[product roadmap](ROADMAP.md), [autonomy roadmap](AUTONOMY_ROADMAP.md),
[implementation priorities](IMPLEMENTATION_PRIORITIES.md) and all
[15 layer backlogs](../roadmaps/README.md). July backlog tables are historical
findings, not a live list of everything still absent. A similar function name,
a merged plan or an available tool is not proof that its acceptance gate is met.

## What was already available at the baseline

- Scope/intrusive entry guards, program profiles, tool discovery/catalog,
  compact exposure, operator skills, CLI access and optional external scanners.
- Registry declarations and extracted registration families, alongside remaining
  code in the server module. A partial extraction is not a completed server split.
- Persistent SQLite runs, task dependencies, leases, heartbeats, budgets,
  invocation receipts, artifacts, findings and recovery. Actual HTTP send
  accounting applies to supported managed paths; browser, raw sockets and
  arbitrary external CLIs are not automatically covered.
- Native capture/repeat/replay primitives and browser actions. Proxy configuration
  does not establish a running intercepting proxy, TLS MITM or vendor integration.
- A selected private-object read verifier and two trusted HTTP/SQLite replay
  recipes, including cookie sessions, middleware controls and resource cleanup.
  These are bounded synthetic fixtures, not arbitrary project preparation.
- Self-host OAST, detection benchmarks, prototype-pollution/GraphQL/race probes,
  findings persistence and Obsidian output using the configured tool name.
  Older next-step text that proposes adding those primitives from scratch is stale.

Evidence: [registry](../moonmcp/registry.py),
[registration families](../moonmcp/families/),
[run store](../moonmcp/runs.py), [managed execution](../moonmcp/execution.py),
[interception primitives](../moonmcp/intercept.py),
[private-read proof](../moonmcp/web/bola_proof.py),
[replay controller](../moonmcp/research.py) and
[replay operating limits](RESEARCH_REPLAY.md).

## Changes in this delivery branch

| Area / original IDs | Concrete delivered change | Scope and remaining limits |
| --- | --- | --- |
| DNS admission: S1/T1 | Empty, invalid, mixed blocked/allowed or failed DNS resolution is rejected before supported HTTP dispatch when private-address blocking applies. | Extends existing pinning. It does not establish proxy isolation or equivalent guards for every raw/CLI transport. See [scope](../moonmcp/scope.py) and [HTTP](../moonmcp/net/http.py). |
| Race lifecycle: WP8 | Own and close every opened connection on partial setup, write/read failure, timeout and cancellation, including late connector completion. | Payload construction, low-level scope admission and heuristic verdict semantics are unchanged. See [implementation](../moonmcp/web/singlepacket.py) and [regressions](../tests/test_singlepacket_cleanup.py). |
| Knowledge: KB1/KB5/KB11/KB15; integrity portion of KB2/KB6/KB10/KB12 | Version all five Python catalogs; check eight collections, required types, IDs, nested signatures/regexes and root-cause foreign keys. Current data has 465 entries across those collections. | KB8/KB9 were already fixed. External JSON/YAML storage and matching/indexing improvements remain open. See [contracts and validation](KNOWLEDGE_VALIDATION.md) and [validator](../moonmcp/knowledge/validation.py). |
| NVD/version handling: IN6/IN15 | Bounded retries for eligible 429/temporary 5xx responses, capped Retry-After/backoff and cancellation/guard stops; conservative prerelease-aware version ranges. | IN6 remains partial: legacy lookup returns None for exhausted provider failure as well as absence. Provider-wide caches/quotas and general advisory-language interpretation are separate. See [CVE client](../moonmcp/intel/cve.py), [version assessment](../moonmcp/intel/zeroday.py) and [regressions](../tests/test_intel_roadmap_completion.py). |
| Reporting: RP7 | Escape Obsidian YAML keys, scalar strings and list items, including quotes, line breaks, controls and strings resembling YAML booleans/numbers. | Evidence redaction RP3/RP9, SARIF enrichment and CVSS extensions are not delivered by this fix. See [Obsidian](../moonmcp/obsidian.py). |
| External execution: EX1/EX2 | Require admission before network-tool spawn; bound combined output to 1 MiB by default, at most 16 MiB; enforce a monotonic deadline and terminate/reap on failure/cancellation. | POSIX process groups and direct Windows-child handling have different guarantees. Shielded cleanup is bounded, but startup settlement can exceed the requested timeout. This is not managed request accounting, egress containment or a binary TOCTOU fix. See [CLI adapter](../moonmcp/external/cli.py) and [operating limits](PERSISTENCE_AND_EXTERNAL_LIMITS.md). |
| Durable state: MS9/MS20/MS21/MS22; append durability related to MS10 | Rotate audit logs with a default 4 MiB segment and three backups, serialized append/rotation and fsync; digest oversized records. Atomically replace bounded snapshot state and expose corruption/write failures, reload stored state and persist clear operations. | Snapshot defaults are 256 snapshots, 10,000 items and 1,000,000 bytes. Local durability is not a crash-proof or tamper-proof journal, database maintenance or unlimited multi-process transactions. See [audit](../moonmcp/audit.py), [monitor](../moonmcp/monitor.py) and [operating limits](PERSISTENCE_AND_EXTERNAL_LIMITS.md). |
| Browser: BR1/BR3 | Mark remote observations untrusted, add bounded advisory content checks, Python-side execution deadlines and bounded startup/cleanup ownership. Default JS evaluation deadline is 20 seconds; the call budget defaults to 60 seconds, is capped at 120 seconds and accepts at most 100 actions. | Advisory matches are not sanitization or proof that unmatched content is safe. Browser state is not a persistent named session, a CPU/VM sandbox or a managed/accounted transport. Real Chromium lifecycle and boundary tests run in a dedicated CI job. See [browser](../moonmcp/web/browser.py). |
| Selected discovery evaluation: IP-01/IP-08 | Add a deterministic independent fixture/evaluator with 16 labelled cases and two methods, including missing objects, expired sessions, long bodies, public/shared objects, failures and budget stops. Track incomplete outcomes, verified claims, causes, requests and replay. | Synthetic tool reliability is not fixed-model discovery improvement. Provider usage/cost are unavailable; third-party project preparation and equal-ready model comparisons remain missing. See [evaluator](../moonmcp/evaluation.py), [fixture](../moonmcp/_evaluation_fixture.py) and [tests](../tests/test_discovery_evaluation.py). |

## IP-01 through IP-08 acceptance status

The bundles contain broader acceptance requirements than the selected read-proof
slice. The table states the actual boundary rather than marking an entire bundle
complete from one regression fixture.

| Bundle | Established implementation | Acceptance still missing |
| --- | --- | --- |
| IP-01 | Existing benchmark primitives plus a small independently labelled deterministic baseline. | Fixed model/input/access budgets, broader unseen variants and a complete detector/preparation comparison. |
| IP-02 | Fail-closed routed HTTP guards, redirect/subresource tests and this branch's untrusted-output/deadline/lifecycle work. | Named persistent sessions, actual browser-send accounting, cancellation at every supported transport boundary and broader protocol isolation. |
| IP-03 | Selected BOLA/workflow coverage preserves incomplete checks; sandbox/research loss remains explicit. | Migration of every composite/provider result. NVD legacy lookup still conflates exhausted failure with absence. |
| IP-04 | Bounded flat-JSON private-read proof checks live identities, declared policy, exact resource/protected fields, a missing-object control and stability. | Generic schemas, write/integrity proofs, automatic policy discovery and general session/role preparation. |
| IP-05 | Selected managed proof sends, receipts, artifacts, budgets, cancellation and replay are implemented. | Autonomous lead selection/validation loop, named-session serialization and supported adapters for excluded transports. |
| IP-06 | Restricted trusted-recipe Docker runtime with intent, leases, bounded output and checked cleanup; external CLI bounds improve local lifecycle safety. | General arbitrary-project admission, generated setup, general durable sandbox recovery and enforced scope-derived egress. |
| IP-07 | Two admitted HTTP/SQLite applications exercise normal preparation and fresh replay, including middleware/session controls. | Third-party project preparation, a generic dependency-aware setup recipe and a general harness-fidelity detector. |
| IP-08 | This branch adds an independent deterministic tool/fixture evaluator. | Fixed-model discovery trials, equal-start/equal-ready preparation comparisons, provider usage/cost and predeclared broader release evidence. |

Run the evaluator without external targets:

    python -m moonmcp.evaluation --trials 5

The supported trial range is 1–20. Its report must retain provenance, limitations,
incomplete outcomes and unavailable measurements. Do not convert synthetic
verified-read counts into a claim of newly discovered real-world vulnerabilities
or measured model gains.

## Layer-by-layer reconciliation

This is a source-based map of important delivered and remaining items, not an
exhaustive reclassification of every low-priority historical finding. Original
IDs remain usable. An unlisted item is not implicitly completed.

| Layer | Already delivered or addressed in this branch | Confirmed remaining work / qualification |
| --- | --- | --- |
| [01 Safety](../roadmaps/01-safety-core.md) | Scope/intrusive entry gates, program profiles and credential-header controls exist. This branch tightens invalid/empty DNS admission for supported HTTP paths. | Do not infer universal raw/CLI/proxy isolation from the HTTP guard. Broader configuration/auth lifecycle work remains separate. |
| [02 Transport](../roadmaps/02-transport.md) | Initial/per-hop HTTP checks, actual-send hooks and direct connection pinning exist. | Connection pooling, provider/per-host policies and parity across optional/proxy/raw transports remain partial; new DNS failure tests do not close all T1 variants. |
| [03 Recon](../roadmaps/03-recon.md) | Central initial URL checks close CR1/RC16/RC28/RC32/RC38/RC41; crawl validates every selected URL; CA1 uses safe_load. | RC8/RC35 direct-helper/derived-host controls, RC43/RC48 passive-apex policy, RC3/RC4 fan-out, RC11/RC12 dependency checks and RC21 sequential metadata remain. Wrapper admission must be distinguished from an in-module guard. |
| [04 Injection](../roadmaps/04-web-injection.md) | WI1 credential extraction and WI4 OOB are opt-in; HTTP/caller guards cover selected WI5/WI7 paths. | WI3/WI13 malformed scheme fallback, WI23 ports, WI9 canary URL validation, WI20 nesting and WI6 error reproducibility remain. Pure offline builders are not automatically exposed network capabilities. |
| [05 Auth](../roadmaps/05-web-auth.md) | WA4/WA5/WA6 XML guards/caps and the selected semantic read-proof path exist. | Legacy WA12 still selects the first extracted reference; WA13 still uses prefix similarity. WA8 remote JWT-header URL validation and general auth-session lifecycle are not completed by the separate proof adapter. |
| [06 Protocol](../roadmaps/06-web-protocol.md) | WP1 throwaway paths, tool-level race consent and this branch's WP8 connection cleanup. | Raw helpers still have separate scope/admission contracts; heuristic observations do not establish arbitrary business effects. |
| [07 Logic](../roadmaps/07-web-logic-modern.md) | WL1/WL2/WL7 dry-run defaults and tool-layer intrusive guards. Selected workflow probes preserve incomplete results. | WL15 literal administrative GraphQL identities, WL6 SPA-shell heuristic leads and broader workflow proof requirements remain. Historical decisions retained some opt-in intrusive detection flows rather than banning pure payload builders. |
| [08 Bypass](../roadmaps/08-web-bypass-exposure.md) | WE18–WE21 stack gates; WE1 active setting and WE4 intrusive MCP entry guard. | WE14/WE15 weak signatures, WE30 tool-name marker and broader module-helper defaults remain. An entry guard is not a proof that every heuristic signature is reliable. |
| [09 Browser](../roadmaps/09-web-browser.md) | BR4 explicit credentials/origin boundaries and BR5 fresh contexts already exist. This branch addresses bounded BR1/BR3 output/execution/lifecycle gaps. | Managed accounting, persistent sessions and complete browser-network isolation remain absent. BR2 stealth and screenshot encryption/redaction are explicit policy/feature choices, not silently completed items. |
| [10 Intel](../roadmaps/10-intel.md) | IN1/IN2 loopback/advertise guards already exist. Search/reader use the shared transport timeout; this branch improves IN6 retry handling and IN15 versions. | IN6 exhausted-lookup ambiguity; IN4 placeholder canaries; IN5/IN21 external-content trust handling; IN7 key-bearing URLs; IN8 plain HTTP; IN9 correlation admission; IN13/IN14/IN16 provider caches/quotas. |
| [11 Knowledge](../roadmaps/11-knowledge.md) | KB8/KB9 typo/FK guard were already fixed; this branch delivers KB1/KB5/KB11/KB15 and shared integrity validation. Existing tests already checked several fields and regexes. | KB2/KB6/KB10/KB12 externalization is not delivered. Matching boundaries, indexing and regex resource policy remain separate. |
| [12 Memory](../roadmaps/12-memory-state.md) | MS3/MS4/MS7/MS8 are fixed or superseded by FTS migration/triggers, transactional clear and exact-host SQL. MS17 preserves zero. This branch improves audit/snapshot bounds and durability. | Memory WAL/read splitting, maintenance/retention, retrieval trust policy and per-kind metrics remain open. Snapshot replacement does not supply those database features. |
| [13 Reporting](../roadmaps/13-reporting.md) | RP6 configured Obsidian identity and RP10 durable findings already exist; RP7 escaping is addressed here. | RP3/RP9 credential/evidence redaction, RP2 empty SARIF URI, RP5 multiline evidence, enrichment and CVSS temporal/environmental/4.0 work remain. |
| [14 External](../roadmaps/14-external.md) | Existing shell-free invocation and wrapper guards; this branch adds EX1 admission and EX2 output/deadline/process lifecycle bounds. | No managed network accounting or enforced child egress; EX4 executable TOCTOU, EX5 builder validation and EX6 normalization enrichment remain distinct. |
| [15 Server](../roadmaps/15-server.md) | SV5 finding audit already exists; registry/family extraction and compact discovery are delivered primitives. | SV1 split is partial; SV2 global context, SV3 error-detail policy, SV4 private SDK metadata, SV6 stack walking, SV7 export audit, SV8 path edge and SV9 automation remain. |

## Product and autonomy work that is still missing

The phase headings in the product roadmap also contain dated next-step text.
Core scope/program/catalog/skill features exist, as do the external registry,
native interception primitives, self-host OAST and several listed detectors.
The following should not be reported as delivered merely because a scaffold or
configuration API exists:

- A running local intercepting proxy with optional TLS MITM, and supported ZAP,
  mitmproxy, Caido or licensed Burp adapters.
- A generic autonomous investigator/librarian loop, capability routing and
  named-session/resource serialization across workers.
- Persistent named browser/auth sessions and refresh/capture recipes connected
  to actual-send accounting.
- Program-specific disclosure templates, richer structured external parsing
  such as nmap XML, and a complete safe nuclei-template lifecycle.
- A uniform managed execution contract for browser/raw/CLI transports, and a
  general arbitrary-project preparation and recovery workflow.
- Independent fixed-model effectiveness/preparation comparisons and provider
  usage/cost evidence. Deterministic benchmarks do not establish context-saving
  or autonomous discovery gains.

See [agent navigation](AGENT_NAVIGATION_PLAN.md) and
[autonomy](AUTONOMY_ROADMAP.md). Existing catalog profiles are not dedicated
coordinator/mapper/validator/reporter exposure profiles. Task role names are not
evidence that those autonomous workers have been implemented.

## Conditional research and the new artifact proposal

The [advanced](ADVANCED_DISCOVERY_ROADMAP.md),
[experimental](EXPERIMENTAL_DISCOVERY_ROADMAP.md),
[relational](RELATIONAL_DISCOVERY_ROADMAP.md) and
[probabilistic](PROBABILISTIC_DISCOVERY_ROADMAP.md) plans remain conditional
research. Their graph/state search, source/trace guidance, paired-world rules,
fault/order exploration and statistical error-control engines are not delivered
by the selected read-proof/evaluation work. Activate a bounded experiment from a
measured miss and its own acceptance gates; do not mark a whole plan done because
related parser, race, memory or agent primitives exist.

[PR #25](https://github.com/Moonwuk/MoonMcp/pull/25), checked when this status was
written, is **open, unmerged and documentation-only** at
[7a946c2](https://github.com/Moonwuk/MoonMcp/commit/7a946c27c2c13407ea329ebd653a70f9ce3e629d).
Its proposed AR-00–AR-06 track covers intake/provenance, offline OCI final and
historical layers, optional registry acquisition, selected GitLab snapshots,
local APK/DEX analysis and optional RuStore acquisition with per-adapter
evaluation. It adds no runtime, dependencies or tests. None of those adapters is
claimed implemented by PR #25 or this delivery branch. AR-00 plus the smallest
offline AR-01 slice is its proposed first implementation; Android/RuStore and
advanced binary tooling have separate prerequisites and are not implicit
dependencies of OCI work. Do not merge the proposal's status into runtime
completion claims.

## Verification and remaining evidence

Use the CI checks attached to the actual assembled source revision as execution
evidence. An earlier aggregate test count does not certify a later change, an
unavailable dependency or a transport that was skipped.

Before merge, record the actual assembled head and its CI results for Python
3.10/3.11/3.12, knowledge validation, browser boundaries/lifecycle, real Docker
replay and the installed wheel's MCP smoke check. Evaluate the independent
fixture separately, retaining its actual JSON report and unavailable-cost fields.
A missing dependency, skipped transport or failed cleanup is a visible coverage
limit, not a passing acceptance gate.

The status remains deliberately partial: it identifies code already present,
delivers selected missing reliability gates and records substantial unfinished
product/research work without treating a roadmap as an implementation.
