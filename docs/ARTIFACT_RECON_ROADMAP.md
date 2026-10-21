# Artifact reconnaissance roadmap

**Reviewed:** 2026-10-21. **MoonMCP baseline:**
[`caad7c9`](https://github.com/Moonwuk/MoonMcp/commit/caad7c9cf135318b3a5155b12facfb190a958dde).
**Status:** proposed implementation work. This document delivers no runtime
integration, dependency, target scan or measured discovery improvement.

## Decision

Extend the materials MoonMCP can inspect, starting with files and historical
layers in an explicitly supplied OCI image. Reuse existing secret/configuration
scanners, local source analysis, runs, evidence and hypothesis workflows. Then
consider selected GitLab source acquisition and an optional Android analysis
branch. Keep remote acquisition separate from offline parsing.

This follows the review of [idkmaybedeveloper's repositories](https://github.com/idkmaybedeveloper).
The useful contributions are concrete acquisition and transformation ideas.
Their presence does not establish that a tool builds, safely processes hostile
inputs, or improves vulnerability discovery. External tools were reviewed
statically; they were not executed or benchmarked during this review.

The [implementation priorities](IMPLEMENTATION_PRIORITIES.md) remain the global
selection guide. AR identifiers below are local delivery units, not a new global
P0 queue. Applicable scope, outcome, accounting and runner defects take precedence.
An offline parser does not depend on completing every IP-01–IP-08 research bundle.
Each implementation PR must identify its owner, selected task, revision, applicable
gates and evidence; it must not mark a whole track complete from a similar API name.

## 1. Reconcile with the implementation

| Existing capability at the reviewed baseline | Proposed addition | Reuse boundary |
| --- | --- | --- |
| Local secret matching, configuration inspection and pattern-based SAST [B1] | Supply selected text from images, repository snapshots and decompiled Android artifacts | Reuse detectors; their matches remain leads, and SAST is not a general data-flow engine. |
| Docker sandbox and two synthetic HTTP/SQLite research recipes [B2] | Inspect OCI manifests, configuration and layer contents | Executing a research container does not inspect the image's historical layers. The first artifact stage runs no image. |
| `git_forensics` for exposed `.git`, including bounded loose-object recovery [B3] | Inventory selected GitLab projects and acquire a fixed source revision | Preserve exposed-Git forensics; do not replace it with a mass-clone utility. |
| `analyze_binary` detects ZIP/APK-family and DEX signatures and scans printable strings; optional .NET decompilation uses `ilspycmd` [B4] | APK unpacking, JADX and supported StringFog transformations | APK/DEX are not wholly unsupported today, but byte-string scanning is not DEX decompilation. |
| Registry, profiles, receipts, request budgets, persistent artifacts, flags and hypotheses [B5] | Add versioned input/provenance records and narrowly scoped adapters | Use the existing stores and workflow; do not create another findings database, graph or generic execution service. |
| Bounded private-read verification and fresh synthetic replay [B2] | Independently investigate applicable leads using existing verification | Do not reimplement BOLA proof or declare it applicable to arbitrary artifact findings. |

The current CLI allowlist does not admit these candidate tools automatically.
Registry membership and launching a subprocess do not establish request accounting.
Follow [tool registration](TOOL_ARCHITECTURE.md), the
[outcome contract](TOOL_OUTCOMES.md) and [agent workflow](AGENT_WORKFLOW.md).

## 2. External candidates and adoption decisions

| Candidate | Verified purpose and limit | Proposed decision |
| --- | --- | --- |
| `trashdump` [E1] | OCI rootfs export or separate layers, backed by `go-containerregistry`; the CLI includes `--layers`. The extractor needs stronger link containment and resource limits. | Adopt the layer-inspection idea. Prefer a bounded native reader for the initial subset; assess the underlying OCI library for a later optional adapter. Do not import the CLI unchanged. |
| `methlab` [E2] | GitLab project pagination and parallel bare cloning/fetching; it is not a vulnerability detector. | Implement selected project inventory and bounded snapshots through MoonMCP's HTTP boundary first. Full clone/history is a later, separately justified capability. |
| `StringMog` [E3] | JADX pass for certain constant StringFog `decrypt` calls: a name-based match, constant arguments, XOR or one AES/CBC construction. | Optional transformation only after basic APK/JADX analysis demonstrates a relevant miss. No claim of universal deobfuscation. |
| `rustore-api-go` [E4] | Unofficial application metadata/search and APK-link retrieval; no APK security analysis or publishing/payment API. | Optional acquisition after a useful local Android pipeline exists. Prefer a small HTTP adapter if compatibility and reuse conditions are established. |
| `dexninja` / `dalvik2` [E5] | `dexninja` provides a Binary Ninja DEX view/disassembly with partial instruction lifting. `dalvik2` is a Rust Dalvik decoder/basic-block analyzer derived from MarginResearch/dalvik; the reviewed fork extends DEX 038+ instruction support. | Defer until a measured DEX-analysis gap needs this additional ecosystem. Credit upstream and review the fork's concrete delta. |

At the reviewed revisions, no license file was found in the complete trees of
`trashdump`, `methlab` or `rustore-api-go`. Record that uncertainty before selecting
copied code or a distributed dependency. Independent implementation from documented
formats/APIs can proceed without adopting those sources. `StringMog` and `dexninja`
include 0BSD licenses; `dalvik2` declares MIT OR Apache-2.0. Recheck the exact selected
revision, notices and dependencies before reuse. A roadmap is not a license grant.

`restash` and `idadiva` concern commercial license generation/patching, and `gpgcat`
embeds messages in PGP streams [E6]. They add no required detection capability to
this track. No integration is scheduled for them.

## 3. Delivery order and dependencies

All AR tasks are **planned**, with no implementation acceptance claimed here.
Scheduling follows the gates below; calendar dates and effort should be set by
the implementing owner after the first fixture run.

| ID | Deliverable | Prerequisites | Completion evidence |
| --- | --- | --- | --- |
| AR-00 | Minimal intake/provenance contract and a small independent fixture baseline | Reviewed source, supported-format decision and reuse/license decision | Baseline misses, clean controls, schemas, budgets and declared comparison criteria |
| AR-01 | Offline OCI configuration, final-file and historical-layer analysis | AR-00; applicable local parser and retention gates | Correct provenance, deletion semantics, bounded resources and existing detector integration |
| AR-02 | Optional acquisition of a selected registry image | AR-01; verified transport/accounting and credential boundaries | Every actual send admitted, digest fixed, incomplete downloads distinguished |
| AR-03 | Selected GitLab inventory and source snapshots | AR-00; the shared transport gates demonstrated for this adapter | Fixed project/commit binding, bounded pagination and accurate coverage |
| AR-04 | Optional local APK/DEX analysis, then a StringMog pilot | AR-00; applicable external-runner gates and a demonstrated Android miss | Plain and supported-obfuscated controls, transformation provenance and explicit partial results |
| AR-05 | Optional RuStore metadata and APK acquisition | AR-04; unofficial API compatibility and transport gates | Package/version/source binding and explicit download/identity failure states |
| AR-06 | Comparative evaluation and release decision for each selected adapter | Starts with AR-00 and repeats at each adapter's acceptance | Published gain or no-gain result, regressions, resource costs and remaining limits |

AR-01 is the first implementation target. AR-03 does not technically depend on
registry support; it can follow AR-00 when a source-audit use case warrants it.
Android and RuStore do not block OCI delivery. AR-06 is a per-delivery gate, not
a reason to wait for every optional branch before releasing a useful parser.

## 4. AR-00 — Intake, provenance and a small baseline

### Scope

Define only the input records required by the first OCI slice, allowing additive
source-specific fields later. Extend existing run artifacts and receipts. Separate
permission to acquire an artifact, permission to inspect it locally and permission
to actively check a discovered endpoint or credential.

Admission must bind a resource, not only a hostname. A registry host does not
authorize every image repository; a GitLab host does not authorize every project.
Use a registered local input or an explicit remote resource selection. Do not
expose arbitrary host-file reads through an unrestricted path argument.

### Minimum record

| Field group | Required information |
| --- | --- |
| Input identity | Source kind, original-byte digest, media type, observed size, acquisition time and sanitized source reference |
| Resource binding | OCI repository/manifest/platform; GitLab instance/project/commit; or APK package/version/hash, as applicable |
| Authorization context | Engagement/run, allowed resource selection, credential principal/session reference and policy revision; never credential values |
| Transformation | Analyzer/version, configuration, parent artifact, selected limits and transform steps |
| Location | Artifact-relative file path and layer/commit; byte/line position or DEX class/method where available; explicitly unknown otherwise |
| Coverage | Requested, acquired and analyzed units; skipped/unsupported units and reasons; integrity/completeness status |
| Evidence | Existing artifact reference and redacted observation; input bytes and derived text must not be confused |

Reuse `moonmcp.result` execution states. Unsupported format, partial analysis,
digest failure and absence of findings must not collapse into the same outcome.
Keep source acquisition status separate from detector verdict and from verification.
Reusing a completed receipt is not an independent experiment.

### Acceptance

- An offline fixture can enter through an explicit input handle, generate a
  redacted observation and attach it to an existing flag without a new store.
- The same fixed input and analyzer configuration preserve the same evidence
  location; changed input, policy or identity cannot silently reuse old admission.
- Retain incomplete coverage after truncation, cancellation and unsupported input.
- Freeze synthetic positive/negative cases and baseline output before changing
  analysis. Label expected source facts independently of the new detector.
- Define retention and cleanup: sensitive source bytes stay in bounded temporary
  staging unless protected retention is explicitly supported and selected. Ordinary
  evidence, logs, flags, memory and model context contain redacted data.

## 5. AR-01 — Offline OCI inspection first

### First implementation slice

Accept one pre-supplied OCI image layout with an explicitly selected image and
platform. Start with documented tar/gzip layer support using the available runtime;
unsupported compression/formats remain visible. Docker-save conversion, remote
pulling, automatic decompressor installation and image execution are outside this
first slice. No Docker daemon is needed to inspect the provided bytes.

Verify selected descriptors and content digests before making trusted provenance
claims. Record the manifest/config/layer identities and distinguish a stored blob's
digest from its uncompressed DiffID. Represent two views:

1. **Final files:** paths/content visible after applying all selected layers.
2. **Historical layer entries:** earlier content, including overwritten or deleted
   files, explicitly labelled with its layer and final-state presence.

Use a logical path/content index and bounded streaming reads where possible. Handle
ordinary and opaque whiteouts, replacement of entry types, and changed files
according to the [OCI layer specification][S1]. Reject invalid duplicate entries
within a layer; replacements across layers are normal. Preserve original artifacts
instead of modifying them to manufacture a convenient final filesystem.

Image configuration may also contain useful strings. Match filesystem layers to
history while skipping `empty_layer=true` entries; do not equate `history[i]` with
`layers[i]`. Missing or inconsistent history means unknown command attribution.
See the [OCI configuration specification][S2].

Feed selected bounded text to existing secret/config/source detectors. Preserve
their own input/file limits and unsupported-language results. Do not treat a path
excluded by SAST, a binary file or an unread layer as clean. Deduplicate repeated
content without losing the list of images/layers/paths in which it occurs.

### Acceptance fixtures

| Fixture | Expected result |
| --- | --- |
| Synthetic secret added in layer A and removed in B | Historical observation names A; final-file view has no such file; no claim that the credential works. |
| File overwritten with clean content | Both versions retain provenance; final observation reflects only the final content. |
| Opaque directory and same-layer replacement | Final view follows OCI semantics independently of tar entry ordering. |
| History containing entries without filesystem changes | Commands are attributed only where the mapping is valid. |
| Tampered blob, missing layer or unsupported compression | Integrity/error or partial coverage is explicit; final absence is not asserted from incomplete layers. |
| Clean configuration and synthetic placeholders | No verified vulnerability; detector false positives are measured. |
| Hostile archive names/links and expansion-heavy data | No writes outside staging, uncontrolled expansion or silent coverage loss. |

The first code PR should contain this narrow offline slice and its fixtures.
Remote clients and mobile dependencies belong in later PRs. The review concern in
`trashdump` is a design input, not a reproduced vulnerability claim against it.

## 6. AR-02 — Optional registry acquisition

Select registry, image repository, immutable manifest digest and platform. A
mutable tag may be resolved once, with the requested tag and resolved digest both
recorded. All subsequent content must be bound to that selected manifest.

Admit and account for every actual request, including token-service challenges,
manifest/index resolution, redirects, retries and blob downloads. Destination
links and auth realms supplied by a server do not grant permission. Bind credentials
to their intended audience; avoid ambient registry keychains by default. Foreign
blob URLs/CDN hosts require explicit permitted routing, or remain unsupported.

If an optional OCI library/CLI cannot enforce the same scope, credential,
actual-send, byte-budget and cancellation requirements, keep that acquisition path
unavailable to managed execution. A subprocess wrapper is insufficient evidence.
Pre-supplied offline inputs remain usable without claiming managed pulling works.

**Acceptance:** controlled registry fixtures cover normal pull, denied repository,
changed tag, wrong digest, malicious auth/redirect destination, token expiry,
interrupted download and byte/request budget exhaustion. Forbidden destinations
receive neither requests nor credentials. Partial bytes cannot become a verified
complete input, and resumption requires a validated unchanged resource/context.

## 7. AR-03 — Selected GitLab source acquisition

Separate discovery of projects from acquisition. Take explicit project IDs or an
authorized bounded namespace selection; require a selected subset before fetching
source. Record which identity observed the projects. Visibility to an authenticated
token is not evidence of anonymous exposure.

The first adapter should obtain bounded file trees/blobs or an archive pinned to a
resolved commit through the existing HTTP boundary. The [GitLab repositories API][S3]
supports these operations. If using its archive endpoint, explicitly disable LFS
blob inclusion for this first stage. Keep submodules, alternate remotes, hooks,
checkout filters, build/install commands and full history out of automatic intake.

Treat namespace names, returned paths and download URLs as untrusted. Bound project
count, pages, source bytes, entries and time. A 403, 429, timeout or budget stop means
limited coverage, not an empty instance. Request accounting covers every page,
commit resolution, redirect and selected content request.

`methlab` produces bare repositories. If a later history-capable adapter reuses
that approach, explicitly extract selected objects/worktree content for file-based
analysis without executing repository configuration, filters or code. A bare clone
directory is not a prepared SAST input. A snapshot cannot claim history coverage.

**Acceptance:** fixtures cover multiple pages, repeated/stale pagination, selected
and excluded projects, changed branch heads, denied access, unsafe returned URLs,
hostile paths and interrupted downloads. Every observation names project, fixed
commit and file; retries cannot silently scan a different revision. Existing
exposed-`.git` behavior remains a separate capability.

## 8. AR-04 — Optional Android analysis

First support a supplied APK/DEX without a store client. Handle APK as a bounded
archive, inventory its DEX/resources and record unsupported splits or formats.
Keep the existing `analyze_binary` behavior available and report its shallow
coverage honestly when deeper analysis is unavailable.

Run a pinned, separately installed JADX only through a reviewed optional adapter.
Do not run the application, execute extracted native libraries or install plugins
on demand. Enforce process, output, disk, time and egress limits. Missing JADX is
an explicit availability result; it must not break the base MoonMCP installation.

After plain JADX provides a baseline, enable a pinned StringMog pass only for
the supported constant-call cases. Compare ordinary JADX output against the same
input with the pass enabled. Dynamic keys, renamed/unmatched classes and unsupported
algorithms remain unresolved. Partially failed decompilation retains partial
coverage even if some useful strings were recovered.

For each derived observation, retain APK/DEX hash, tool/plugin versions and the
original class/method/location when available. Generated Java line numbers alone
are not original-source locations. Record package/version and signer identity when
verified; distinguish parsed signing metadata from successful signature verification.
An unknown signer must stay unknown, not become an asserted trusted identity.

**Acceptance:** independently labelled fixtures include plain strings, supported
XOR/AES StringFog calls, unsupported/dynamic calls, multidex, malformed DEX, partial
decompilation and ZIP expansion limits. The plugin recovers the expected constants
without inventing plaintext for unsupported cases. New URL/secret candidates remain
observations and retain provenance; they do not trigger automatic network checks.

## 9. AR-05 — Optional RuStore acquisition

Activate only when AR-04 has a useful, measured local workflow and there is a
specific application acquisition need. Verify the unofficial API's current
compatibility independently of the Go example; preserve its version limitations.

Bind an explicit package and selected version to sanitized metadata, acquisition
time, download source and the resulting APK hash. Check actual package/version and
signer information where supported; a store response alone is not cryptographic
identity verification. Missing or mismatched decisive identity data blocks claims
that the acquired APK is the requested trusted release.

Apply resource scope and credential/redirect gates to store and download/CDN
requests separately. A failed download-link request is a visible partial result,
not a successful metadata summary silently missing its APK. Expired links, changed
versions and truncated downloads require new explicit outcomes. Local input remains
the fallback if this optional provider is unavailable.

**Acceptance:** controlled recorded/synthetic responses cover metadata success,
link failure, redirects, selected-version mismatch and incomplete APKs. Only a
separate authorized compatibility check can establish that the live API works.
This task does not add store publishing or payments.

## 10. Shared processing and output requirements

These requirements apply to the relevant implementation slice; they do not require
building a general-purpose artifact service before AR-01.

- **Bound actual work.** Set and record finite numeric caps before release:
  compressed/expanded bytes, bytes per entry, entry count, layers, path depth,
  nested archives, subprocess CPU/RSS, wall time, temporary disk and output.
  Check observed streaming data, not only archive headers or Content-Length.
- **Contain files.** Prefer processing entries without materializing links. If
  staging is needed, constrain actual path resolution, including symlink/hardlink
  chains, PAX path/link overrides, absolute/parent paths and platform aliases.
  Reject special devices/FIFOs and unsupported sparse entries; no rootfs mounting.
- **Preserve runtime responsiveness.** Bound or isolate parsing/decompilation so
  hostile input cannot occupy the MCP event loop indefinitely. Cancellation must
  stop child work; lost workers leave verified cleanup or an explicit unresolved
  staging/lease record. Do not promise physical secure erasure.
- **Redact every output channel.** Cover source contexts, neighboring matches,
  filenames, URLs, image config/history, subprocess errors and logs. Canary secrets
  must not appear in previews, evidence summaries, flags, memory or model input.
  Do not expose a plain hash of a low-entropy secret as a redaction substitute.
- **Keep source trust separate.** Repository text and decompiler output are
  untrusted data, including embedded instructions and terminal control characters.
  They cannot change policy, enable tools, execute commands or expand target scope.
- **Separate evidence from a claim.** Recovering a credential-shaped string proves
  only those bytes were present in that artifact. It does not prove credential
  validity, current external exposure or authorization to use it. Attach leads to
  existing flags/hypotheses; require a suitable independent check for a finding.

## 11. AR-06 — Measure value and decide what to ship

Freeze inputs, labels, versions and budgets with AR-00, then evaluate each selected
slice. Use two comparisons so acquisition is not mistaken for better detection:

1. **Equal supplied artifacts:** existing supported analysis versus the new parser
   or transformation on the same files; measure recovered labelled facts and costs.
2. **Equal initial access and budgets:** baseline workflow versus acquisition plus
   analysis; count all acquisition work, manual preparation and incomplete attempts.

Report unique adjudicated leads, precision/recall on labelled fixtures, false
vulnerability claims, unsupported/partial coverage, reproducibility, requests,
bytes, CPU/RSS, temporary disk, elapsed/manual time and optional model costs.
Track verified vulnerability causes separately where an independent authorized
verification exists. More strings, flags, calls or installed tools are not more
vulnerabilities. Include held-out variants and clean inputs; publish no-gain results.

**Per-slice release gate:**

- The selected acceptance fixtures and applicable boundary tests pass on a named
  revision; normal supported inputs retain compatible behavior.
- There is an independently checked useful capability gain or a documented
  operational benefit. If neither is shown, defer expansion and report the result.
- No forbidden send, credential/canary leak, staging escape or concealed incomplete
  result is accepted as a tradeoff for higher recall.
- New tool policies accurately report availability/accounting. Managed support
  remains blocked where nested execution has not met its real boundary tests.
- Findings and documentation distinguish implemented, tested, available, deferred
  and measured claims. Install hints or merged planning documents prove none of them.

## 12. Deferred work and next PR

Defer Binary Ninja/dexninja integration, general DEX data-flow analysis, arbitrary
deobfuscation, whole-instance GitLab mirroring, full Git history acquisition,
automatic credential use, execution of downloaded images/apps, automatic package
installation and a new evidence/vault service. Activate a specific item only with
a recorded miss, an owner, supported dependency/reuse conditions and a bounded
evaluation. Preserve the project's stdlib-first base installation.

**Next implementation PR:** AR-00 plus the smallest AR-01 slice: a registered local
OCI input, bounded layer/config parsing, final-versus-historical attribution,
existing secret detection, redacted evidence and the paired deleted-file/clean
fixtures. Include applicable malformed-input and output-channel cases, then publish
the AR-06 result for that slice. Add registry acquisition only in a subsequent PR.

## Sources and review limits

The MoonMCP review uses the baseline commit above; local links navigate the checkout.
E1–E5 identify reviewed external revisions; upstream and exclusion links provide
navigation. Recheck upstream before implementation. Specification/API links are
living references consulted on 2026-10-21. Source review does not establish that
external tests passed.

- **[B1] Existing analyzers:** [secrets](../moonmcp/recon/secrets.py),
  [configuration](../moonmcp/recon/config_audit.py), [SAST](../moonmcp/recon/sast.py).
- **[B2] Delivered verification/replay:** [verification](VERIFIED_AUTHORIZATION.md),
  [replay](RESEARCH_REPLAY.md), [private-read implementation](../moonmcp/web/bola_proof.py).
- **[B3] Existing Git forensics:** [gitdump.py](../moonmcp/recon/gitdump.py).
- **[B4] Binary analysis:** [binary.py](../moonmcp/recon/binary.py).
- **[B5] Integration contracts:** [registry](../moonmcp/registry.py),
  [execution](../moonmcp/execution.py), [runs](../moonmcp/runs.py),
  [flags](../moonmcp/flags.py), [CLI allowlist](../moonmcp/external/cli.py).
- **[E1] trashdump:** [extractor](https://github.com/idkmaybedeveloper/trashdump/blob/5f227e9e5ec7baf295cd67abde05e503dd430a30/internal/dump/dump.go),
  [CLI layer option](https://github.com/idkmaybedeveloper/trashdump/blob/5f227e9e5ec7baf295cd67abde05e503dd430a30/cmd/trashdump/main.go),
  [reviewed tree](https://github.com/idkmaybedeveloper/trashdump/tree/5f227e9e5ec7baf295cd67abde05e503dd430a30).
- **[E2] methlab:** [implementation](https://github.com/idkmaybedeveloper/methlab/blob/2785b54c09895591456c6eac77720663bf193a95/main.go),
  [reviewed tree](https://github.com/idkmaybedeveloper/methlab/tree/2785b54c09895591456c6eac77720663bf193a95).
- **[E3] StringMog:** [transformation](https://github.com/idkmaybedeveloper/StringMog/blob/44a95d3cbe3dfb0d73966c75a316f287e0a69f99/src/main/kotlin/blahaj/digital/stringmog/StringFogPass.kt),
  [license](https://github.com/idkmaybedeveloper/StringMog/blob/44a95d3cbe3dfb0d73966c75a316f287e0a69f99/LICENSE).
- **[E4] rustore-api-go:** [API description](https://github.com/idkmaybedeveloper/rustore-api-go/blob/e85807058d071215b828cced4c607dbfb9dcffa1/README.md),
  [reviewed tree](https://github.com/idkmaybedeveloper/rustore-api-go/tree/e85807058d071215b828cced4c607dbfb9dcffa1).
- **[E5] Android reverse engineering:** [dexninja](https://github.com/idkmaybedeveloper/dexninja/blob/d0b0da97949a8dc2bfb450d808e32329fa55d3d0/README.md),
  [dexninja license](https://github.com/idkmaybedeveloper/dexninja/blob/d0b0da97949a8dc2bfb450d808e32329fa55d3d0/LICENSE),
  [dalvik2 manifest](https://github.com/idkmaybedeveloper/dalvik2/blob/a106be4c1b15d441c61eb7382f0fabe4795ece15/dalvik/Cargo.toml),
  [Dalvik decoder](https://github.com/idkmaybedeveloper/dalvik2/blob/a106be4c1b15d441c61eb7382f0fabe4795ece15/dalvik/src/decode.rs),
  [dalvik upstream](https://github.com/MarginResearch/dalvik).
- **[E6] Excluded candidates:** [restash](https://github.com/idkmaybedeveloper/restash),
  [idadiva](https://github.com/idkmaybedeveloper/idadiva), [gpgcat](https://github.com/idkmaybedeveloper/gpgcat).
- **[S1] Format semantics:** [OCI layers][S1].
- **[S2] Image provenance:** [OCI configuration][S2].
- **[S3] Source acquisition:** [GitLab repositories API][S3].

[B1]: ../moonmcp/recon/sast.py
[B2]: VERIFIED_AUTHORIZATION.md
[B3]: ../moonmcp/recon/gitdump.py
[B4]: ../moonmcp/recon/binary.py
[B5]: TOOL_ARCHITECTURE.md
[E1]: https://github.com/idkmaybedeveloper/trashdump/blob/5f227e9e5ec7baf295cd67abde05e503dd430a30/internal/dump/dump.go
[E2]: https://github.com/idkmaybedeveloper/methlab/blob/2785b54c09895591456c6eac77720663bf193a95/main.go
[E3]: https://github.com/idkmaybedeveloper/StringMog/blob/44a95d3cbe3dfb0d73966c75a316f287e0a69f99/src/main/kotlin/blahaj/digital/stringmog/StringFogPass.kt
[E4]: https://github.com/idkmaybedeveloper/rustore-api-go/blob/e85807058d071215b828cced4c607dbfb9dcffa1/README.md
[E5]: https://github.com/idkmaybedeveloper/dexninja/blob/d0b0da97949a8dc2bfb450d808e32329fa55d3d0/README.md
[E6]: https://github.com/idkmaybedeveloper/restash
[S1]: https://github.com/opencontainers/image-spec/blob/main/layer.md
[S2]: https://github.com/opencontainers/image-spec/blob/main/config.md
[S3]: https://docs.gitlab.com/api/repositories/
