# MoonMCP vs. nuclei — cited coverage audit

*Two independent web-researched passes (a "steelman nuclei" coverage pass and a
"structural-gaps" pass), each grounding every claim in a source URL. This is the
evidence behind the `scan_coverage` tool and `moonmcp/external/nuclei.py`
(`NUCLEI_DELEGATE` vs `NATIVE_EDGE`). Headline: don't reinvent nuclei; invest only
where it structurally can't reach.*

## Headline numbers

Across **49 audited tools** (yes = 1.0, partial = 0.5, no = 0):

| Coverage | Tools | Share |
|---|---|---|
| **Fully covered by nuclei** (delegate) | 14 | ~29% |
| **Partially covered** (nuclei has the mechanism, we add packaging/differential) | 15 | ~31% |
| **Not covered** (structural blind spot) | 20 | ~41% |

**Weighted ≈ 44% of MoonMCP's detector surface is already covered by nuclei.** The
uncovered ~41% is *not* random leftovers — it is precisely the **stateful /
two-identity / raw-byte-timing / business-intent** class that a stateless
per-template matcher cannot express, and that the mass-scanning crowd therefore
leaves under-reported.

## What nuclei actually does (verified, cited)

- **Protocols** (v3): `http, dns, network(TCP), ssl, file, headless, websocket, code, javascript, whois`; multi-protocol + a JS `flow` engine for author-scripted chains. [SYNTAX-REFERENCE](https://raw.githubusercontent.com/projectdiscovery/nuclei/master/SYNTAX-REFERENCE.md) · [v3 blog](https://blog.projectdiscovery.io/nuclei-v3-featurefusion/) · [flow docs](https://docs.projectdiscovery.io/templates/protocols/flow)
- **DAST fuzzing** (`-dast`, `fuzzing:` schema over query/header/path/body/cookie): SQLi, XSS, SSTI, CSTI, CRLF, CMDi, SSRF (blind **and** response), open-redirect, LFI/RFI. Caveat (PD's own): "limited to URLs with query parameters" — fuzzes existing params, doesn't brute hidden ones. [fuzzing blog](https://projectdiscovery.io/blog/nuclei-fuzzing-for-unknown-vulnerabilities) · [fuzzing examples](https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-examples)
- **Template library** ≈ **12,000 files** (`http/` 9,281 incl. `cves/`, `exposures/`, `misconfiguration/`, `default-logins/`, `takeovers/`, `technologies/`; `cloud/` 659; `dast/` 240; …), ~1,496 KEV-covering. This community library is nuclei's real moat. [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) · [Nov-2025 blog](https://projectdiscovery.io/blog/nuclei-templates-november-2025)
- **Auth** (v3.2 secret file: static/dynamic headers, cookies, login flows — **scoped one-identity-per-domain**), matchers-condition/DSL/extractors, **Interactsh OAST**, a **race** directive (`race:true`/`race_count`), `ssl` `jarm()`, favicon mmh3 + `-uncover` Shodan pivot. [auth-scans](https://docs.projectdiscovery.io/opensource/nuclei/authenticated-scans) · [race docs](https://docs.projectdiscovery.io/templates/protocols/http/race-conditions) · [interactsh](https://projectdiscovery.io/blog/nuclei-interactsh-integration)

## Where nuclei structurally fails (verified, cited)

- **Per-template matcher, not a stateful reasoner** — "does not crawl, click through forms, or reason about business logic… multi-step flows are invisible… cannot reason about state between requests." [appsecsanta](https://appsecsanta.com/dast-tools/nuclei-alternatives)
- **Two-identity authorization (BOLA/IDOR)** — DAST "tests with one set of credentials; 200 OK ⇒ assumed pass." Catching it "requires a tester that holds two accounts and checks every boundary." nuclei's secret file binds one identity per domain → no A-vs-B diff inside a matcher. [stingrai](https://www.stingrai.io/blog/api-scanners-miss-bola-idor-authorization-testing) · [apyguard](https://www.apyguard.com/resources/blog/the-invisible-threat-of-idor-and-bola)
- **Raw framing / timing-differential smuggling** — `rawhttp`/`unsafe:true` exists but leaks: nuclei "breaks the request" at a `0`-chunk on POST and rewrites `Transfer-Encoding`/`Content-Length`; and it matches response **content**, not read-**timeout** deltas (the 2025 0.CL/TE.0/Expect technique). [issues/5416](https://github.com/projectdiscovery/nuclei/issues/5416) · [discussions/3910](https://github.com/orgs/projectdiscovery/discussions/3910) · [PortSwigger desync](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- **Race** — gate-based directive, chronically broken (sequential w/ 2 s delay; re-regressed in 3.2/3.3; fixed only in v3.7.0) and **not** the single-packet attack (Burp/Turbo Intruder). [issues/5713](https://github.com/projectdiscovery/nuclei/issues/5713) · [single-packet attack](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local)
- **Session/baseline differential** — matchers are self-contained booleans that misfire on 401/403/version fragments; nuclei ships cache-**poisoning** but no cache-**deception** (authed-vs-anon prime/re-read). [matchers wiki](https://github.com/projectdiscovery/nuclei-templates/wiki/How-to-Write-Unique-Matchers-in-Nuclei-Templates) · [cache-poisoning.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/generic/cache-poisoning.yaml)

## Tiers (what to keep, what to stop)

**NUCLEI-CANNOT — genuine structural edge, invest here:**
`authz_probe` & `access_control_check` (two-identity BOLA), `workflow_probe`
(step-skipping), `cache_deception_probe` (session differential), `desync_modern_probe`
+ `http_behavior` (raw-socket timeout-differential framing), `backend_probe` /
behavioural-infra (cross-sample statistical inference), `config_audit` forge-chain
*classifier*, `surface_diff` (cross-run state).

**NUCLEI-WEAK — modest/packaging edge, honest caveats:**
`race_probe` (**upgraded**: now a real **single-packet attack** via HTTP/1.1 last-byte
synchronization — `moonmcp/web/singlepacket.py`, all N requests complete within ~1 ms,
neutralizing the jitter the old `asyncio.gather` was bound to; the tighter HTTP/2
single-packet variant is deferred as it needs the `h2` dependency),
`logic_probe`, `response_leak_probe`, `reset_poison_probe`,
`path_bypass_probe`, `tls_behavior`, `oauth_probe`, `recover_sourcemaps`, `jwt_crack`
(really a jwt_tool/hashcat wrapper), `desync_probe`, `confirm_finding`, `origin_discovery`.

**NUCLEI-FINE — nuclei + its template community win; stop investing:**
`crlf_probe`, `ssrf_metadata_probe` (cloud-metadata SSRF is response-signature +
interactsh, nuclei's wheelhouse), `debug_exposure`, `stack_probe`, `edge_map`.
Keep them as agent-callable coverage, but they carry **zero hit-rate advantage**.

## Non-detector architecture (no nuclei analogue — but scope it honestly)

- **Scope-gating choke-point** — `guard_connect()` resolves the host and blocks if any
  resolved IP is private/reserved (closes in-scope-hostname→127.0.0.1/169.254.169.254
  and DNS-rebinding), every decision audited. A **safety/governance** edge that makes an
  *autonomous LLM agent* deployable — not a detection edge.
- **Shared cross-agent memory hub** (SQLite FTS, trust-tagged) — agent orchestration, not bug-finding.
- **Offline knowledge bases** — be honest: **not** an edge over nuclei's 12k-template
  library; frame as agent-reasoning context, not competing coverage.
- **Strix orchestration under human confirmation** — the lead→PoC bridge. Every edge tool
  emits `review` **leads, not confirmations**; the uplift is contingent on this pipeline.
  [usestrix/strix](https://github.com/usestrix/strix)

## Strategic verdict

The premise "everyone runs nuclei ⇒ what nuclei misses has a higher hit-rate" is
**directionally true, refined**: the edge is the **class** (stateful / two-identity /
raw-timing / business-intent), *not* "self-written" per se — several of our own tools
(the FINE tier) duplicate a more mature engine and confer no advantage. Three caveats:
(1) these classes are hard and FP-prone, which is *why* every edge tool returns leads,
so the uplift is contingent on a strong lead→confirmed pipeline (`confirm_finding` +
Strix); (2) the uplift only materializes on targets with stateful/multi-identity
surface (APIs, checkout/auth flows, multi-tenant) — a static site gives the edge tools
nothing to bite on; (3) `race_probe` now ships a real single-packet implementation
(HTTP/1.1 last-byte sync), moving it from "modest" toward genuine edge. **Invest in the
CANNOT tier + the governance/orchestration layer; stop competing with nuclei on the
FINE tier.**
