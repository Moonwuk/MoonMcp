# Changelog

All notable changes to MoonMCP are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

### Added
- **`response_format=concise|detailed` on the heavy-output tools (ergonomics).**
  Recon tools can emit large payloads (hundreds of subdomains, a full crawl tree,
  a long request history); streaming all of it into the agent's context every call
  burns the token budget it needs for the hunt. A new `moonmcp/shape.py` trims
  lists longer than 20 items to a preview + a `{"_truncated": N, ...}` sentinel;
  the tool exposes `response_format` (default `"concise"`) so the agent asks for
  `"detailed"` only when it needs the full set. Wired into the six heaviest tools —
  `crawl`, `recon_target`, `http_history`, `memory_graph`, `list_findings`,
  `analyze_js` (not all 169; a small result is unchanged, and a concise result is
  a strict subset of the detailed one so nothing is silently lost).
- **`search_tools` — progressive tool discovery (ergonomics).** A 169-tool
  surface is past the point where handing an agent every schema at once helps
  (tool-selection accuracy drops as the visible set grows). `search_tools(query)`
  ranks the tools by relevance to a keyword/phrase (`"graphql"`, `"jwt"`,
  `"cache poisoning"`) and returns a short list — name match outranks family
  outranks gist — so the agent retrieves the few relevant tools instead of
  scanning all of them. Pairs with `tool_catalog` (the full grouped map) and
  `plan_target` (what to run next on a target). Pure ranker in
  `moonmcp/toolsearch.py`; offline.
- **`plan_target` — next-action ranking for any agent (ergonomics).** Codifies
  the idea-gen skill's attack-vector brainstorming as a *tool*, so an agent works
  the target well even without the skill loaded. Reads the knowledge graph
  (discovered tech/services/endpoints/params) and the findings store
  (confirmed/tried), cross-references a signal→probe map, and returns a ranked,
  non-redundant list of next probes — each with the exact tool, the recon signal
  that motivated it, and an impact priority. A class already covered by a finding
  is flagged `already_evidence` and sorts down (confirm or move on, don't re-run
  blind); empty memory points at the baseline recon tools. The inverse of
  `promote_lead`/`leadpipe` (which routes an *already-found* lead to its PoC).
  Pure/offline scoring in `moonmcp/planner.py`; a drift guard test asserts every
  tool it can emit actually exists.

### Changed
- **Standardised `suggested_next` on the detection probes (ergonomics).** Every
  detector emits a verdict, but an agent still has to decide the next move. A new
  `moonmcp/nextstep.py` centralises that: given a probe + its verdict it names the
  concrete tool(s) to run next (confirm the lead, poll the OAST callback, or pivot
  to the related class), and the probes attach it as a `suggested_next` field so
  the agent chains without re-reasoning. Wired into the core detection/recon
  probes — `sqli_probe`, `cmdi_probe`, `ssti_probe`, `lfi_probe`, `nosqli_probe`,
  `xxe_probe`, `ssrf_probe`, `graphql_check`, `graphql_probe`, `jwt_analyze`,
  `fingerprint`, `crawl` (`interp_probe` already computed its own). Only positive
  verdicts get a suggestion — a clean result stays quiet. Not every one of the
  168 tools carries it (a recon/meta tool's next step is context-dependent); a
  drift-guard test asserts the map never points at a non-existent tool.
- **De-duplicated the OAST-collection epilogue** (docs/PROJECT_AUDIT.md 1.1). The
  ~10-line "read the self-hosted catcher, else poll the provider and parse"
  block was copy-pasted across ~9 OOB probe bodies (jwt_jku, second-order SQLi,
  passive-scan, sqli/cmdi OOB lanes, ssrf, xxe, ssrf_protocol, fastjson). It now
  lives once in `oastmod.collect_interactions(ctx, token)`; the probes call it.
  Behavior-preserving (full suite green); ~80 lines removed. The `oast_poll`
  diagnostic tool keeps its own distinct return semantics and is unchanged.

### Added
- **MCP tool annotations derived from the scope markers.** From the research
  agenda (docs/RESEARCH_AGENDA.md) + audit convergence: every registered tool now
  carries MCP `ToolAnnotations` so a cooperating host can auto-insert a
  confirmation gate on the loud/offensive tools (read/recon on by default,
  anything that could touch state prompts). Mapping is derived from the existing
  `@active_tool`/`@safe_tool` markers — intrusive probes get
  `readOnlyHint=false, destructiveHint=true, openWorldHint=true`; non-intrusive
  active tools `readOnlyHint=true, openWorldHint=true`; safe/offline tools
  `readOnlyHint=true`. These are **hints only** — the `@active_tool` scope guard
  remains the real enforcement (the spec says clients must treat annotations as
  untrusted), so this adds a host-UI signal without weakening the gate.
- **CVE risk triage (`cve_triage`).** From the research agenda
  (docs/RESEARCH_AGENDA.md, top direction) — `cve_lookup` returns CVSS, which is
  *theoretical* severity; real triage needs exploitation likelihood. The new tool
  enriches an NVD record with **EPSS** (FIRST.org exploitation probability),
  **CISA KEV** (is it actively exploited in the wild?), and a public-**PoC** signal
  (an NVD "Exploit"-tagged reference), then folds them into one composite score —
  `0.35·EPSS + 0.30·KEV + 0.20·CVSS + 0.15·PoC` — with a KEV hard-override
  clamping any actively-exploited CVE to the CRITICAL band (≥76) and a KEV+PoC
  ×1.15 boost. So a "medium CVSS but on the KEV list" bug sorts above a "critical
  CVSS but no known exploitation" one. Passive third-party data (NVD/FIRST/CISA),
  no packets to any target; the scoring is a pure, offline-testable function.
  `moonmcp/intel/cverisk.py`.
- **CSP policy-strength analysis in `analyze_headers`.** From the project audit
  (docs/PROJECT_AUDIT.md 6.1 — the one confirmed coverage gap): the header audit
  used to grade Content-Security-Policy present-vs-absent, so a worthless-but-
  present CSP scored as full protection. `moonmcp/recon/csp.py` now parses the
  policy and weights the CSP's contribution by how much it actually blocks script
  injection — `'unsafe-inline'` (unless neutralised by a nonce/hash),
  `'unsafe-eval'`, a wildcard `*`, `data:`/`blob:`/`http:` script sources, and the
  worst case of no `script-src`/`default-src` at all all downgrade the score, with
  every reason surfaced under a new `csp_weaknesses` field. Softer hardening gaps
  (permissive `object-src`, missing `base-uri`) are reported but don't move the
  score, so a genuinely strong policy like `default-src 'self'` still grades full
  marks. Passive, no extra requests.
- **SAML XML Signature Wrapping probe (`saml_xsw_probe`).** Detection-only,
  gap #8/8 (the last) from the Burp technique research pass. SAML responses
  carry a *detached* signature — a `<ds:Signature>` whose `Reference` points
  at the `<saml:Assertion>` it covers *by ID*, not by tree position — so if
  the SP's signature validator resolves that reference by ID while its
  business logic picks an assertion by some naive positional rule instead
  ("first assertion in the document", "last one", "direct child of
  Response"), an attacker can relocate the original validly-signed assertion
  and plant a forged, unsigned one where the positional logic will actually
  look. Give it a captured, legitimately-signed SAMLResponse (base64 or raw
  XML) and the SP's ACS URL: it first reports a static structural read (no
  network) — assertion/signature counts, dangling signature references — then
  resends the document via three representative topologies (not the full
  academic XSW1-8 taxonomy — `sibling_before`/`sibling_after`/
  `wrap_extension`, mirroring `cmdi_probe`'s small-representative-set
  discipline), each cloning the signed assertion, stripping the clone's
  signature, and forging its identity. `reflected_forged_identity` — the
  forged identity appearing in a variant's response but in neither an
  accepted-baseline nor a signature-corrupted-control response — is the
  strong, replay-noise-independent confirmation signal (SAML's own
  anti-replay protections can make simple status/length baselines noisy on
  their own). Never forges a valid signature — the wrapping trick IS the
  attack. `moonmcp/web/saml.py`.
- **Generic differential "interpretation" prober (`interp_probe`, Backslash
  Powered Scanner-style).** Detection-only, gap #7/8 from the Burp technique
  research pass — a meta-probe, not a class-specific one. Most injection
  probes look for a KNOWN signature of a KNOWN vulnerability class; this one
  asks a more basic question first: is this parameter's value being
  *parsed/interpreted* at all, or just stored/echoed as an opaque blob? Sends
  five small, distinctive markers — each built to reveal ONE kind of
  character-level processing (backslash/escape handling, quote/string-context
  handling, NUL-byte truncation, `/./` path-segment normalization, bare `{}`
  template/structural-token handling) — and checks whether each was echoed
  literally or transformed. A single marker firing is a coin-flip (a WAF or
  encoder could incidentally strip one character class); **two or more
  independent markers agreeing** is the corroboration bar before this calls
  anything more than a "weak" signal, mirroring `ssti_probe`'s multi-engine
  downgrade discipline. Never asserts a specific vulnerability class —
  `suggested_next` points at which class-specific probe (`sqli_probe`,
  `cmdi_probe`, `lfi_probe`, `ssti_probe`, `parser_diff_probe`, ...) to run
  given which markers fired. `moonmcp/web/interp.py`.
- **Known-vulnerable JS library detector (`js_library_scan`, Retire.js-lite).**
  Detection-only, gap #6/8 from the Burp technique research pass: matches script
  URLs/filenames (and, best-effort, an in-body version banner) already surfaced by
  `analyze_js`/`crawl` against a small bundled table of historically-vulnerable
  library versions — jQuery <3.5.0 (DOM XSS via `.html()`), AngularJS <1.8.0
  (CSP/expression-sandbox bypass), Lodash <4.17.21 (prototype pollution),
  Moment.js <2.29.2 (ReDoS), Handlebars <4.5.3 (prototype-pollution RCE gadget),
  Bootstrap <4.1.2 (tooltip/popover XSS). Pure regex + version-tuple comparison —
  no content-hash database to maintain (a deliberate zero-dependency trade
  against Retire.js's fuller but harder-to-keep-current coverage).
  `moonmcp/recon/jslibs.py`.
- **Blind XXE detection (`xxe_probe`).** Detection-only, gap #5/8 from the Burp
  technique research pass — two lanes: **format confusion** rewrites a JSON or
  form-urlencoded body into an equivalent XML document (porting Content Type
  Converter's core trick) and resends it under the ORIGINAL Content-Type, since
  some frameworks parse a body by sniffing its shape rather than strictly
  enforcing the declared type; **`oob`** injects a `<!DOCTYPE>` external entity
  referencing a MoonMCP **OAST** canary and polls for a DNS/HTTP callback — a
  callback is unambiguous proof the parser dereferenced an external entity.
  Never reads file contents (no exfil channel is built), mirroring
  `ssrf_probe`/`fastjson_oast_probe`'s callback-only design. `moonmcp/web/xxe.py`.
- **Deserialization-format fingerprint (`deserialize_fingerprint`, Freddy-lite).**
  Detection-only, gap #4/8 from the Burp technique research pass: 100% passive
  byte/base64 signature scan over an already-captured cookie/header/hidden-field
  value — Java native serialization (`ACED0005` raw or base64 `rO0AB...`), .NET
  ViewState (LosFormatter `FF01` header — also flags whether it looks encrypted vs.
  plaintext), PHP `serialize()` objects (`O:<len>:"Class":`), Python pickle
  (protocol 2-5 markers), Ruby `Marshal.dump`, and Fastjson/Jackson polymorphic
  JSON (`@type`/`@class`). No new network traffic, no forged gadget chain, never
  invokes ysoserial/PHPGGC/ViewGen itself — reports the format as a lead for the
  caller to hand to the right tool via Strix. `moonmcp/recon/deserialize.py`.
- **Path traversal / LFI content-disclosure (`lfi_probe`).** Detection-only, gap
  #3/8 from the Burp technique research pass: depth-escalating `../` (x1/3/6/8),
  null-byte, double-URL-encoded, and Windows-style traversal variants at a param,
  confirmed by a genuine **file-content signature** (the `root:x:0:0:` /etc/passwd
  anchor, win.ini `[fonts]`/`[extensions]` markers, and related patterns already in
  the `path-traversal` knowledge base) — proof the traversal reached the
  filesystem, distinct from `waf_bypass_probe`'s canary (which only proves a WAF
  let the payload's *shape* through) and `path_bypass_probe` (401/403
  ACL-normalization bypass, not file disclosure). Reads only universally-present,
  non-sensitive files — never app source, credentials, or config; deeper
  extraction is weaponisation → Strix. `moonmcp/web/probes.py`.
- **JWT algorithm-confusion forgery (`jwt_alg_confusion`).** Detection-only, gap #2/8
  from the Burp technique research pass: re-signs a captured RS256/ES256 token as
  HS256/384/512 using the **public key's exact PEM text** as the HMAC secret — the
  classic "verifier doesn't pin the algorithm family" bug, the highest-impact JWT
  attack after `alg:none`. Preserves the original header's `kid` (and other fields)
  so a key-by-`kid` lookup still resolves; only `alg` flips. No RSA/EC keygen
  needed — just the public key text, often already in hand via `oauth_probe`'s
  `jwks_uri`. Purely offline — never auto-replays the forged token; the caller
  confirms it themselves (or via `http_repeater`). `moonmcp/web/jwt.py`.
- **Blind OS command injection (`cmdi_probe`).** Detection-only, ported from Burp's
  command-injection extension techniques: a small, non-combinatorial set of shell
  separators (`;` `|` `&&` `&` backtick `$()`) each carrying only a side-channel
  payload — `sleep N`, confirmed by the same monotonic-timing check `sqli_probe`'s
  `time_based` lane uses (rules out network jitter / a uniformly-slow endpoint), or
  an **OAST** DNS/HTTP callback. Deliberately never sends an output-eliciting
  payload (`id`, `cat /etc/passwd`, `dir`) — success is proven by timing or a
  callback only, command output is never displayed or exfiltrated; weaponisation
  (reverse shell, output read) is delegated to Strix. `moonmcp/web/probes.py`.
- **Deep GraphQL probing (`graphql_probe`).** The GraphQL classes that pay out even
  when introspection is disabled, past `graphql_check`'s introspection test: **batch
  abuse** (an array of operations honoured in one request → a rate-limit/brute-force
  amplifier and the batched-login credential-stuffing primitive), **field-suggestion
  schema recovery** (a deliberately typo'd field → *"Did you mean …?"* leaks real
  field/type names, recovering the schema without introspection), **alias** honouring
  (many operations per document), and a nested-traversal **BOLA** lead to confirm with
  `access_control_check` / Strix. Detection-only — benign queries, small batch, no
  mutations. `moonmcp/web/graphqldeep.py`.
- **Git-history forensics (`git_forensics`).** The deep follow-up to `vcs_exposure`
  and a stable-Critical source: when a `.git` is exposed, it reconstructs history
  from what the server already serves (read-only GETs; nothing written) and mines it
  — `.git/config` remote URLs embedding **credentials**, the `.git/logs/HEAD` reflog
  (commit SHAs + author names/emails + messages), the `.git/index` **tracked file
  list** (flags `.env`/`id_rsa`/`*.sql`/`credentials`, parsed from the binary DIRC
  format), and a **bounded loose-object walk** (`objects/xx/…` zlib-inflate → commit
  → tree → blob) running the secret scanner over every blob and commit message.
  Packed history (delta-compressed `*.pack`) is **detected and reported** for
  git-dumper/Strix rather than silently skipped. Secrets are redacted; each is a lead
  to confirm live. `moonmcp/recon/gitdump.py`.
- **WebSocket detection (`ws_probe`).** The WebSocket surface that most scanners
  skip. Speaks the RFC 6455 handshake by hand (stdlib — no `websockets` dependency)
  to confirm an endpoint (HTTP 101 + a valid `Sec-WebSocket-Accept`) and run the
  flagship **Cross-Site WebSocket Hijacking (CSWSH)** check: a repeat handshake with
  a foreign `Origin` that still upgrades proves the server doesn't validate Origin, so
  a cookie-authenticated socket is hijackable cross-site. Reports a **lead** (confirm
  the socket is cookie-authed and sensitive before reporting; weaponise via Strix).
  `probe_message` (opt-in, off by default) additionally sends one clearly-marked
  benign text frame to detect echo/reflection. Scope-gated. `moonmcp/web/websocket.py`.
- **Web-research toolkit (OSINT).** `web_read(url)` — fetch a public page and return
  clean readable content (title, meta description, main text with scripts/styles/nav
  stripped, outbound links, word count); the reader that pairs with search. Not
  target-scoped (reads third-party research) but the block-private SSRF guard still
  refuses internal/metadata IPs, no engagement auth is sent, and returned text is
  treated as untrusted. `web_search` is now **multi-engine & resilient** — DuckDuckGo
  HTML → DDG Lite → Bing fallback, URL de-duplication, and a `site=` domain filter —
  so one engine failing or rate-limiting no longer blinds the search. New
  `web-research` skill. `moonmcp/intel/reader.py`, `moonmcp/intel/search.py`.
- **Memory: knowledge graph + learning loop.** The shared memory hub gains a typed
  **knowledge graph** — entities (host / endpoint / param / technology / service /
  cve / credential / asset) and typed relations (`affects` / `on` / `uses` /
  `caused_by` / `confirms` / …) — so findings become a queryable structure, not flat
  notes; `add_finding` now auto-links a finding to its host and endpoint.
  `memory_link` / `memory_graph` build and read it, `memory_brief(target)` rolls up
  *what we know about a target* (entities, findings, leads, lessons), and
  `memory_lesson(add/recall)` gives the agent a durable, cross-target **learning
  loop** so tradecraft carries forward between sessions. New `memory` skill.
  `moonmcp/memory.py`.
- **Database & data-store attack surface (detection-only).** A large multilingual
  research synthesis (`docs/DATABASE_RESEARCH.md`) executed as ~14 probes:
  `db_exposure` (raw-socket unauth sweep — Redis/Mongo/memcached/ES/CouchDB/InfluxDB/
  YARN/TiDB), `nosqli_probe` (Mongo operator + `$where`), `second_order_sqli_probe`
  (stored write→read SQLi), `orm_leak_probe` (Django/Prisma/Rails relational-lookup),
  `fastjson_oast_probe` (Java autoType → OAST), `ssrf_protocol_probe` (gopher/dict →
  internal datastore), six opt-in `sqli_probe` lanes (context/oob/time/json-waf/
  multibyte/header), `firebase_exposure` + `supabase_exposure` (cloud DBaaS),
  `stack_probe` vector-DB/Druid-session extensions, `debug_exposure` DB panels, a
  managed-DB DSN/token classifier in `extract_secrets`/`analyze_config`, and regional
  KB packs (KR/JP/CN DBMS error signatures + APAC WAF fingerprints).
- **WAF-bypass & advanced injection detectors.** `parser_diff_probe` (HTTP
  parser-differential / WAF-bypass multiplier — UTF-7/overlong decode + duplicate-key/
  comment/BOM/bare-LF-multipart tolerance), `graphql_nosqli` (GraphQL resolver → Mongo/
  Mongoose operator injection via the variables transport), and `cspp_probe` (client-side
  prototype pollution, tested safely in MoonMCP's own headless browser — never mutates
  the target). Each hardened by an adversarial multi-agent verification pass.
- **Behavioural infrastructure detectors.** Infer the infra's shape from response
  *variance*: `backend_probe` (cluster N responses → backend fleet behind an LB +
  **patch drift** across nodes + clock skew), `dns_behavior` (wildcard DNS, DNS
  load-balancing, IPv6, dangling-CNAME/takeover surface), `vhost_probe`
  (Host-header validation + host-header injection reflection), `ratelimit_probe`
  (throttle threshold + `X-Forwarded-For` per-IP bypass), `tls_behavior` (real-host
  vs bogus-SNI cert diff → SNI routing / default-cert origin hint + weak-TLS flags),
  `edge_map` (CDN/WAF/cache/proxy layering), `http_behavior` (raw HTTP/1.x edge-case
  reactions — bare-LF / oversized / bad-method → lenient-parsing/desync surface).
  `moonmcp/recon/infra.py`; each covered by a behaving eval endpoint.
- **Active detectors + built-in OAST + eval harness.** `ssti_probe` (multi-engine
  template-eval differential), `sqli_probe` (error signatures + benign boolean
  pair), `ssrf_probe` (OAST-callback confirmation), `cache_probe` (unkeyed-header
  reflection × cacheability) — detection-oriented, intrusive-gated, feeding
  `confirm_finding`. `oast_selfhost` runs a stdlib callback catcher so blind-vuln
  confirmation needs no third party. A detection **eval harness**
  (`tests/test_eval_detectors.py` + deliberately-vulnerable endpoints) asserts each
  probe detects its class and doesn't false-positive. `moonmcp/web/probes.py`,
  `moonmcp/intel/oast_server.py`.

### Fixed
- **Security & correctness hardening — 21 verified bugs from a whole-project audit**
  (partitioned multi-agent finders → independent per-finding verification; each fix
  pinned by a regression test in `tests/test_bugfixes.py`). Scope/SSRF guard: an
  IPv4-mapped IPv6 literal no longer defeats IPv4 CIDR allow/deny matching; the HTTP
  redirect follower refuses `file://`/`ftp://`/`data:` (opener drops File/FTP/Data
  handlers); `sourcemaps` re-checks an attacker-controlled cross-origin
  `sourceMappingURL`; `run_scanner` scope-checks comma/space-delimited arg tokens
  (no IMDS smuggling); credentials are stripped on cross-origin redirects; the
  connect-guard fails closed on a resolver error; `jwt_jku_probe`/`workflow_probe`
  scope the right parameter; safety env flags keep their safe default on an
  unrecognised value. Correctness: `tls_inspect` decodes the raw DER (getpeercert()
  is `{}` under CERT_NONE, so SAN extraction was silently dead); plus FP/FN fixes in
  `nosqli`/`logic`/`redirect`/`behavior`/`firebase`/`oast`/`desync`/`config_audit`
  and a memory trust-downgrade fix.

## [Released — v0.1.x, PR #1]

### Added
- **Finding confirmation + CVSS.** `confirm_finding` proves a lead before you
  report it — a baseline-vs-test differential weighing reflection, status/length/
  timing change, injection signatures, and out-of-band (OAST) callbacks into a
  verdict (`confirmed`/`likely`/`inconclusive`/`unconfirmed`), optionally recording
  a confirmed hit. `cvss_score` computes a CVSS 3.1 base score + severity band
  from a vector or metrics. `moonmcp/confirm.py`, `moonmcp/cvss.py`.
- **Tool-exposure profiles + a CLI bridge.** `MOONMCP_PROFILE` (`full`/`strix`/
  `passive`/`knowledge`/`recon`) + `MOONMCP_EXPOSE_TOOLS` / `MOONMCP_HIDE_TOOLS`
  expose a *curated slice* of MoonMCP; `moonmcp tools` and `moonmcp call <tool>`
  let a **shell-based agent** (e.g. Strix's command tool, or CI) invoke MoonMCP
  tools non-interactively and get JSON — so MoonMCP can be a shared brain/memory/
  guard for a tool without an MCP client. `server_status` shows the active profile.
- **Shared memory hub** (`memory_add` / `memory_search` / `memory_get` /
  `memory_stats` + `memory://recent`): a persistent, cross-agent SQLite store
  (stdlib, FTS5-ranked search) so a chain of agents shares state instead of
  re-deriving it. Every item is **trust-tagged** (`untrusted` scraped content vs
  `curated` conclusions) — the anti-prompt-injection guard — and `add_finding`
  auto-mirrors findings in as curated. `moonmcp/memory.py`.
- **Finding triage** (`triage_findings`): dedupe exact duplicates, rank unique
  findings by severity × frequency, and surface *systemic* issues (the same
  finding across many targets). Dry-run, or `apply=true` to collapse in place.
- **Burp-style interception (native).** `http_repeater` (send one raw/structured
  request → full response + passive scan), `intruder` (payload-marker sweep with
  status/length/reflection diffing, intrusive-gated), `passive_scan` (all passive
  analysers over one response), and `http_history` (in-memory request/response log
  for replay). Pure stdlib, scope-gated (`moonmcp/intercept.py`). Live proxy +
  ZAP/mitmproxy/Burp adapters are the next Phase-4 increment (legal only).
- **Deep Kali integration.** External-tool registry expanded to **36 tools**
  across 11 categories (typed `ToolSpec` with native fallback + install hint,
  auto-detected on PATH). Intrusive external scanners (fuzzers, port scanners,
  active vuln scanners) are gated behind `MOONMCP_ALLOW_INTRUSIVE` in
  `run_scanner`; `external_tools` now returns a categorised inventory.
- **`tool_catalog` + Claude Code skill.** A self-describing map of all tools
  (grouped by family, each tagged `scope_gated` / `intrusive`, with the
  recommended recon→report workflow) and a packaged skill
  (`.claude/skills/moonmcp/`) so an agent orients itself and drives the tools in
  the right order. `moonmcp/catalog.py`; a test keeps the map in sync with the
  registered tools.
- **`@active_tool` — one scope gate.** Scope logic (target normalization +
  scope/SSRF check + intrusive gate + audit + structured-error envelope) is now
  centralized in a single decorator; every packet-sending tool declares it and a
  CI guard test asserts none ships un-gated.
- **Bug-bounty program profiles** (`program_add` / `program_use` / `program_list`
  / `program_remove`): each program carries its own scope **and its own
  identifying header** (e.g. `X-HackerOne-Research: <handle>`) + optional
  User-Agent, auto-attached to in-scope requests. Persist across restarts via
  `MOONMCP_STATE_DIR`. `docs/ROADMAP.md` tracks the multi-phase plan.
- **Engagement auth context** (`auth_set` / `auth_clear`) threaded into every
  in-scope request, unlocking authenticated testing.
- **Access control / IDOR** (`access_control_check`) — user-A vs user-B vs
  anonymous response diffing.
- **Out-of-band callbacks** for blind vulns: `oast_configure`, `oast_generate`,
  `oast_poll`, `oast_list` (interactsh/Collaborator-compatible).
- **Headless browser**: `browser_open`, `browser_eval` (browser console),
  `browser_interact` (click/fill/submit/wait + cookies & localStorage).
- **Internet search**: `web_search` (keyless) and `search_dorks` (Google/Bing
  dork generator).
- **Discovery**: `discover_parameters` (hidden params), `analyze_js` (deep JS
  endpoint extraction + source maps), `parse_openapi` (spec → endpoint inventory),
  `cloud_buckets` (S3/GCS/Azure enumeration), `probe_batch` (parallel liveness).
- **Redirects**: `trace_redirects` (hop-by-hop chain analysis).
- **Reporting**: `export_findings` (SARIF 2.1.0 / JSON).
- **Continuous monitoring**: `surface_diff` / `surface_snapshots` (baseline +
  diff, optional disk persistence via `MOONMCP_STATE_DIR`).
- **Knowledge bases**: injections (29 classes), techniques & PoCs (115),
  privilege escalation (129 techniques + 68 tools), server-side vulnerabilities
  (44) + root-cause taxonomy (13), WAF reference (24). Plus 8 operator prompts.
- CI coverage gate; `py.typed` marker; tag-triggered PyPI release workflow.

### Fixed
- **SSRF guard** hardened: resolve-then-check and obfuscated-IP canonicalization
  (decimal/hex/octal/short + IPv4-mapped IPv6), applied at every HTTP hop and the
  raw-socket choke point — an in-scope hostname resolving to a private/internal IP
  is now blocked.
- `run_scanner` refuses file-I/O flags/paths (no arbitrary read/write past scope).
- Dead JWT expiry/nbf check now runs; `safe_tool` catch-all; various
  edge-case parser fixes surfaced by adversarial review.

## [0.1.0]
- Initial MoonMCP: scope-first, stdlib-first bug-bounty reconnaissance MCP server.
