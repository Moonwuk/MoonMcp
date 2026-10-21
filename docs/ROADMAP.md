# MoonMCP roadmap

For the dated source-based reconciliation of delivered work and open acceptance
requirements, see [implementation status (2026-10-21)](ROADMAP_STATUS_2026-10-21.md).
Historical phase labels below do not certify that an entire phase is complete.

MoonMCP is a **stateful security-research harness exposed through MCP**. The
[harness architecture and delivery roadmap](RESEARCH_HARNESS_ROADMAP.md) defines
the current host/server responsibility split and the next external-agent
effectiveness experiment. It reuses existing runs, tools, evidence and recovery.

Authorised scope remains a first principle. Actual execution/accounting guarantees
depend on the supported adapter; initial target admission does not establish
uniform browser, raw-protocol or subprocess egress control. Consult the status map
and operating guides before relying on a path.

This roadmap is a living document. Phases are ordered by value; within a phase
the items are roughly dependency-ordered.

---

## Phase 1 — One scope, many programs *(in progress)*

**Goal:** make the scope guard a single place that is trivial to extend, and let
every bug-bounty program carry its own identity (custom header + User-Agent).

- **`@active_tool` decorator.** One decorator wraps a tool with, in order: the
  `safe_tool` structured-error envelope, the intrusive gate, the scope check +
  resolve-then-check SSRF guard, and the audit record. A tool author no longer
  hand-writes `_require_scope(...)`; they just declare `@active_tool()` (or
  `@active_tool(intrusive=True)`). Scope logic now lives in exactly one place.
- **Scope-coverage guard test.** A test enumerates every registered tool and
  asserts it is either explicitly passive (a small, reviewed allowlist) or
  carries the `@active_tool` gate marker — so a new packet-sending tool can never
  be merged un-gated by accident.
- **Program / engagement profiles.** A `Program` bundles a name, its scope
  (in/out), a **custom bug-bounty header** (each program wants its own, e.g.
  `X-Bug-Bounty: you@wearehackerone.com`), and an optional per-program
  User-Agent. Activating a program swaps in its scope and auto-attaches its
  header + UA to every **in-scope** request (via the existing `AuthContext`
  merge path — credentials still only travel to in-scope hosts). Profiles persist
  to `MOONMCP_STATE_DIR` so they survive restarts. Tools: `program_add`,
  `program_use`, `program_list`, `program_remove`.

## Phase 2 — Discoverability (a skill + a catalog) ✅

**Goal:** an agent should immediately understand what MoonMCP can do and reach
for the right tool.

- ✅ **`tool_catalog` tool.** Returns the tool inventory grouped by family
  (setup, passive OSINT, light active, intrusive, orchestration, knowledge,
  reporting, external), each with a one-line purpose, its `scope_gated` /
  `intrusive` flags, and the suggested recon→report workflow — a machine-readable
  map of the server (`moonmcp/catalog.py`; a test asserts it never drifts from the
  registered tools).
- ✅ **A Claude Code skill** (`.claude/skills/moonmcp/SKILL.md`) that teaches an
  agent the MoonMCP workflow (status → catalog → scope/program → passive → light
  active → intrusive-with-consent → report), the rules of engagement, and when to
  use which tool, so the capabilities are self-describing rather than tribal
  knowledge.
- ✅ **Assessment process skills.** `assessment-planning`,
  `systematic-validation`, and `run-coordination` adapt the planning,
  evidence-before-claims, and resumable execution patterns from the
  MIT-licensed obra/superpowers project to MoonMCP's scope/budget/coverage model.
  The remaining agent-runtime work is tracked in `docs/AUTONOMY_ROADMAP.md`.

## Phase 3 — Deep Kali / external-tool integration ✅ (core)

**Goal:** when MoonMCP runs on Kali (or any box with the usual toolbox), it
should safely orchestrate the installed CLIs and parse their output — never
reinventing nmap/nuclei/ffuf, just driving them behind the scope guard.

- ✅ Expanded the external-tool registry to **36 tools** across 11 categories
  (subdomain, dns, http, crawl, url, content, port, vuln, cms, tls, decompile),
  each a typed `ToolSpec` with a native fallback + install hint, auto-detected on
  PATH.
- ✅ **Intrusive external scanners** (fuzzers, port scanners, active vuln
  scanners) are now gated behind `MOONMCP_ALLOW_INTRUSIVE` in `run_scanner`, on
  top of the scope check — matching the native intrusive tools.
- ✅ `external_tools` returns a **categorised inventory** (installed + intrusive
  flags + install hints); the file-I/O-flag refusal and per-arg host scope-check
  are unchanged.
- ⏭️ Still to do: richer structured parsing (e.g. nmap XML → findings) beyond the
  JSONL auto-parse.

## Phase 4 — A Burp-like interception layer *(legal integrations only)*

**Goal:** the "intercept / repeat / replay" workflow, inside MoonMCP.

> **Licensing note.** MoonMCP will **not** bundle, download, or incorporate
> pirated or cracked commercial software (e.g. cracked Burp Suite Professional).
> That is a copyright/licence violation and off the table. The plan below uses a
> native implementation plus **legitimate** integrations only.

- ✅ **4a — native Burp-style primitives** (`moonmcp/intercept.py`): the workflow
  an agent actually drives — `http_repeater` (send one raw/structured request,
  get the full response + passive scan), `intruder` (payload-marker sweep with
  status/length/reflection diffing; intrusive-gated), `passive_scan` (all passive
  analysers over one response), and `http_history` (in-memory request/response
  log for replay). All scope-gated and rate-limited; pure stdlib, works
  everywhere.
- ⏭️ **4b — live intercepting proxy**: a local proxy that records in-scope traffic
  for the `browser_*` tools to route through. HTTP is stdlib; **TLS MITM** needs
  on-the-fly cert generation, so it will require an optional crypto dependency and
  a generated local CA (off by default).
- ⏭️ **4c — legitimate integrations** (adapters, opt-in): OWASP **ZAP** (REST API),
  **mitmproxy**, **Caido**, and licensed **Burp** (official REST / Montoya API).
  No cracked binaries — supported automation APIs only.

## Phase 5 — Reporting, triage & self-hosting (proposals)

- ✅ **Finding dedup & triage** (`triage_findings`): collapse exact duplicates,
  rank unique findings by severity × frequency, and surface *systemic* issues
  (the same finding across many targets) — feeds `report` / `export_findings` /
  `export_obsidian`.
- Per-program **report templates** (a program's preferred disclosure format).
- **OAST self-host** helper (stand up / point at your own interactsh) so blind
  callbacks don't depend on a third party.
- **nuclei template management** (list/select/update template sets safely).
- **OAuth / session capture** via the browser tools to feed `auth_set`.

## Phase 6 — Composable autonomy (Strix as a co-tool) ✅ (foundation)

**Goal:** an external agent uses MoonMCP's research state and checks, with optional
focused delegation to [Strix](https://github.com/usestrix/strix). The delegate
returns candidate evidence for independent review and reproduction. The external
agent owns strategy; neither a delegate report nor a successful tool call is an
automatic finding confirmation. Measure the cost and result of delegation.

- ✅ **`strix-orchestration` skill** — a reference playbook for selecting
  in-scope leads and collecting delegated evidence. Review that evidence before
  promotion through `add_finding` / `triage_findings` / `report`. The existing
  prompt base (`prompts.py` RoE + PoC gate) supplies instructions, not an execution
  boundary or independent proof.
- ✅ **Reference MCP wrapper** (`examples/strix_mcp/server.py`) exposing
  `strix_run` / `strix_result` / `strix_available`. It can check the initial
  network target with `moonmcp.scope.ScopeManager`; code/repository inputs and
  missing scope support have different behavior. It does not establish managed
  subprocess accounting or egress containment. See the exact
  [integration boundaries](STRIX_INTEGRATION.md).
- ✅ **CLI/library bridge examples.** An external delegate with suitable shell
  or Python access can reach `moonmcp call <tool>` / `moonmcp tools` and the Python
  library. Tool profiles select complementary MoonMCP capabilities. Registered
  tool gates apply to those calls; they do not govern everything the delegate
  does. Verify compatibility with the chosen delegate version.
- ✅ **Shared memory hub** (`moonmcp/memory.py`) — the keystone that lets a chain
  of agents share state instead of re-deriving it. A persistent SQLite store
  (stdlib, FTS5-ranked search, `MOONMCP_STATE_DIR/memory.db`) with **trust +
  provenance on every item** (`untrusted` scraped content vs `curated`
  conclusions) for inspection. A `curated` label is not independent validation
  or an injection-containment boundary. Tools: `memory_add`, `memory_search`,
  `memory_get`, `memory_stats` + the `memory://recent` resource; `add_finding`
  auto-mirrors findings in as `curated`. External agents can reuse these records;
  an autonomous librarian remains proposed work.
- ✅ **Native validation layer** (`confirm_finding` + `cvss_score`): differential
  (baseline vs test) + injection-signature + out-of-band (OAST) confirmation →
  `confirmed`/`likely`/`inconclusive`/`unconfirmed`, plus a CVSS 3.1 base score —
  for selected native checks. The bounded private-object read verifier and its
  remaining limits are documented in [verified authorization](VERIFIED_AUTHORIZATION.md).
  These outputs still require evidence review and applicable controls.
- ✅ **Active detectors + self-host OAST + eval harness.** Differential probes for
  selected classes — `ssti_probe` (multi-engine), `sqli_probe` (error+boolean),
  `ssrf_probe` (OAST callback), `cache_probe` (unkeyed reflection × cacheability),
  all intrusive-gated and feeding `confirm_finding`. `oast_selfhost` is a built-in
  stdlib callback catcher (no third party). A detection **eval harness** runs each
  probe against a deliberately-vulnerable endpoint (measurable recall + regression
  guard).
- ⏭️ Next: select a measured remaining gap using the
  [harness roadmap](RESEARCH_HARNESS_ROADMAP.md) and current status map. Prototype
  pollution, GraphQL and race primitives already exist; broader discovery and an
  autonomous librarian remain separate work. Existing deterministic evaluation
  does not establish model-driven discovery gains.

---

## Non-negotiables (every phase)

- **Authorised testing only.** The scope guard and SSRF guard are never
  bypassed by a feature.
- **Stdlib-first.** New capabilities keep a pure-standard-library path; optional
  dependencies only ever *improve* accuracy.
- **No pirated software, ever.** Integrations use vendor-supported or
  open-source automation APIs.
- **stdout is sacred.** It is the JSON-RPC channel; all logging goes to stderr.
