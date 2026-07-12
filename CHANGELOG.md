# Changelog

All notable changes to MoonMCP are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

### Added
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
