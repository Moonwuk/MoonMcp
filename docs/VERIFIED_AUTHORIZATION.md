# Implemented authorization verification and outcome repairs

This delivery implements a bounded HTTP private-object read check using existing
`authz_probe`, execution accounting, run artifacts and lead navigation. It addresses
selected work from the 2026-10-15 capability audit and proposed IP-01/IP-03/IP-04/IP-05
bundles. It does not complete the research roadmaps or demonstrate improved autonomous
discovery performance.

## Agent workflow

1. Establish authorised scope and a run. Obtain synthetic/live test credentials and
   the expected object policy from the application owner or an independently defined
   fixture. Configure the owner's credentials with `auth_set`.
2. Use ordinary `authz_probe` findings as review leads. A `direct_bola` confirmation
   plan now names `authz_probe`, the missing proof inputs, and its request requirement;
   producing the plan does not execute it.
3. Supply the manifest below and distinct `second_headers` to `authz_probe`, preferably
   through `run_execute`. The completed path makes **eight GET requests**: owner and
   observer identities; owner and observer object reads; a known-missing control;
   both identities again; the owner object again to check stability.
4. Read the execution receipt first. An interrupted, blocked or ambiguous receipt
   cannot establish successful verification even if it retains useful observations.
   Then inspect `proof.verified`, individual checks and limitations.
5. A managed call saves an immutable `authorization_check` artifact, including
   incomplete evidence. Its ID/hash/reference appear in `evidence`. These references
   can be attached through the existing flag/hypothesis APIs. No hypothesis or finding
   is automatically promoted. A hash establishes stored-content integrity, not truth.
6. Independently prepare fresh authorised state and repeat with a new invocation key
   before external reporting. Reusing an idempotency key only reads the earlier receipt;
   it is not a new experiment. Preserve both evidence records and any disagreements.

## Manifest example

These are synthetic placeholders. The application has flat JSON identity and object
endpoints on the same origin. Identity replies expose `subject` and `tenant`; objects
expose string fields `id`, `type`, `owner`, `tenant` and the requested protected fields.
Adapt the manifest to actual supported data, not by removing application checks.

```json
{
  "target": "https://fixture.test/orders/100",
  "second_headers": {"Authorization": "Bearer SYNTHETIC_OBSERVER_TOKEN"},
  "proof": {
    "version": 1,
    "identity_url": "https://fixture.test/me",
    "control_url": "https://fixture.test/orders/known-missing",
    "owner": {"subject": "alice", "tenant": "north"},
    "observer": {"subject": "bob", "tenant": "south"},
    "resource": {"id": "100", "type": "order", "owner": "alice", "tenant": "north"},
    "policy": {
      "id": "owner-only-read-v1",
      "source": "application owner's declared read policy",
      "visibility": "private",
      "allowed_subjects": ["alice"]
    },
    "protected_fields": ["secret"]
  }
}
```

The verifier uses isolated explicit owner/observer headers with ambient auth and
proxy rewrite rules suppressed. Redirects are not followed. It validates the live
subject/tenant, exact resource binding and nonempty protected fields in bounded,
complete JSON responses, including data beyond the heuristic's first 4 KiB.
The observer must receive matching declared metadata and protected values; the
owner's checked fields must remain stable. Public/shared or explicitly allowed
reads return `not_applicable` before probing. Unsupported/missing policy must be
resolved by the caller, not inferred from an HTTP status or body similarity.

Returned evidence contains response-body digests and matched field names, not raw
private field values or credential headers. URLs and declared subject/resource
metadata remain visible; do not put credentials or private field contents there.
Receipts persist an argument/context hash rather than raw authentication arguments.

`not_verified` means this bounded check did not establish this claim; it is not an
application-wide assurance. Missing/expired identities, incorrect owner binding,
an unexpected control response, truncation or changed state produce `inconclusive`.
The legacy heuristic mode remains available, with honest incomplete outcomes.

## Evidence and roadmap status

The [2026-10-21 reconciliation](ROADMAP_STATUS_2026-10-21.md) tracks subsequent
changes. Run `python -m moonmcp.evaluation --trials 5` for the versioned deterministic
comparison; CI preserves its JSON report. This is not a model or autonomous
vulnerability-discovery comparison.

The follow-up [local HTTP/SQLite research recipe](RESEARCH_REPLAY.md) now supplies a
strict opt-in adapter with a pinned image, durable resource records, bounded output,
checked cleanup, and fresh capsule replay against a separate application process.
The table below describes the original verification delivery; the first follow-up
was limited to one synthetic recipe and did not complete IP-07/IP-08.

A subsequent extension admits a second WSGI/cookie recipe and checks a deliberately
invalid middleware-bypassing harness against the same object through normal HTTP.
Both recipes now have fresh independent replay and crash-recovery controls. This
extends the IP-07 evidence; arbitrary project preparation and IP-08 model comparisons
remain outstanding. See the replay guide for exact entry points and limitations.

| Bundle | Delivered here | Still outside this delivery |
| --- | --- | --- |
| IP-01 | Independent fixture policy, vulnerable/fixed implementations, private/public/shared cases, failure and long-body cases | General held-out discovery baseline and fixed model trials |
| IP-02 | Guard registration failure propagates; guard-operation failure aborts/closes; both browser paths enforce routed HTTP scope; real Chromium redirect/click/subresource tests | Managed browser send accounting, full protocol/network isolation, streaming/resource budgets |
| IP-03 | Explicit subcheck coverage, retained partial leads, MCP outcome consistency; sandbox command/cleanup failures | Migration of every other legacy composite producer |
| IP-04 | Flat-JSON, same-origin, private-read proof with live subjects, declared policy, protected fields and controls | General named-session lifecycle, other resource schemas, write claims, policy discovery |
| IP-05 | Existing managed sends, budget stops, receipt replay/cancellation tests, immutable proof artifacts, executable tool named in lead plan | Automatic research agent loop, broader method routing and independent real-target replay |
| IP-06 | Original sandbox defaults plus opt-in trusted recipes with a pinned image, durable resource leases, bounded output and verified cleanup/recovery | Arbitrary repository commands, general network policy and production isolation |
| IP-07 | Two trusted HTTP/SQLite and WSGI/cookie recipes, normal-entry fidelity checks, portable capsules and fresh replay | Arbitrary project preparation, additional stacks and supported transports |
| IP-08 | Deterministic heuristic/proof comparison on independent labelled synthetic cases, incomplete outcomes and replay costs | Fixed-model trials, real-project generalisation and autonomous discovery gains |

## Browser and container compatibility

Scoped browser calls now reject out-of-scope HTTP subresources as well as navigation.
With supplied credentials, requests stay on the initial origin even if another
origin is in scope. Service workers are disabled. The guard obtains responses with
automatic redirects disabled, checks Location, then fulfils the browser request.
This buffers responses; it is not a streaming browser proxy or network sandbox.
Other browser protocols and full resource accounting remain outside this guarantee.
Websites requiring third-party resources may report incomplete rendering.

The Docker runner's default is `network=none`, no added capabilities, no host gateway,
and a process limit in addition to CPU/memory limits. Existing Python callers can
still explicitly choose another network/capability set; the MCP schema has not gained
such an override. A URL regex in a command is never an egress policy. Runtime Docker
is not required by the mocked lifecycle tests and remains excluded from managed
execution. No production-container isolation claim follows from these tests.

## Validation entry points

- `tests/bola_fixture.py`: application policy and isolated two-tenant transport.
- `tests/test_bola_proof.py`: class-specific positive/negative/incomplete cases,
  credential omission, managed request budgets, artifact integrity, cancellation,
  receipt replay and fresh fixture repetition.
- `tests/test_probe_coverage.py`: errors cannot aggregate to clean negatives;
  partial results, uncertain mutations and cancellation retain their semantics.
- `tests/test_sandbox_outcomes.py`: Docker CLI failure simulation and default launch
  arguments; these are not real daemon lifecycle tests.
- `tests/test_browser_guards.py` and `tests/test_browser.py`: isolated guard failures
  plus actual Chromium local-server checks. CI installs Chromium in a separate job;
  environments without Playwright skip the live cases explicitly.

Run the normal Ruff, mypy and coverage-gated pytest jobs as well. These regression
checks evaluate implementation correctness, not an agent's vulnerability-discovery
precision, recall or comparative cost.
