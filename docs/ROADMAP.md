# MoonMCP roadmap

MoonMCP is a **scope-aware** bug-bounty & reconnaissance MCP server. Everything
below keeps that first principle: every packet-sending capability passes a single
authorization choke point, and MoonMCP is only ever pointed at assets you are
authorised to test.

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

**Goal:** an agent (opencode / hermes / Claude) drives MoonMCP *and* a
heavyweight autonomous validator side-by-side, in one window — MoonMCP *finds*
cheaply and scope-first, [Strix](https://github.com/usestrix/strix) *confirms*
with a working PoC. This is the composable answer to Strix's monolithic
"graph of agents": both are MCP tools of the same agent, not a separate app.

- ✅ **`strix-orchestration` skill** — the playbook: recon/detect with MoonMCP →
  delegate only high-value in-scope leads to Strix → merge validated findings
  back into `add_finding` / `triage_findings` / `report`. Reuses the existing
  prompt base (`prompts.py` RoE + PoC gate) to instruct Strix.
- ✅ **Reference MCP wrapper** (`examples/strix_mcp/server.py`) exposing
  `strix_run` / `strix_result` / `strix_available`, **scope-gated by reusing
  `moonmcp.scope.ScopeManager`** so Strix inherits MoonMCP's guard, plus
  `docs/STRIX_INTEGRATION.md` (opencode + hermes wiring).
- ⏭️ Next: a MoonMCP-native validation layer (`confirm_finding` — differential +
  OAST + repeater → `confirmed`/`unconfirmed`) and CVSS scoring, so cheap
  confirmation happens in MoonMCP before paying for a Strix run.

---

## Non-negotiables (every phase)

- **Authorised testing only.** The scope guard and SSRF guard are never
  bypassed by a feature.
- **Stdlib-first.** New capabilities keep a pure-standard-library path; optional
  dependencies only ever *improve* accuracy.
- **No pirated software, ever.** Integrations use vendor-supported or
  open-source automation APIs.
- **stdout is sacred.** It is the JSON-RPC channel; all logging goes to stderr.
