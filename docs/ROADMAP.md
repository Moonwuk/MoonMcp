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

## Phase 3 — Deep Kali / external-tool integration

**Goal:** when MoonMCP runs on Kali (or any box with the usual toolbox), it
should safely orchestrate the installed CLIs and parse their output — never
reinventing nmap/nuclei/ffuf, just driving them behind the scope guard.

- Expand the external-tool registry (auto-detect on PATH) beyond the current set,
  with a native stdlib fallback documented for each.
- Scope-gated, structured wrappers that parse tool output into MoonMCP findings.
- Keep the existing hardening: file-I/O flags are refused, every host/URL token
  in the args is scope-checked, external tools are gated behind
  `MOONMCP_ALLOW_EXTERNAL_TOOLS`.

## Phase 4 — A Burp-like interception layer *(legal integrations only)*

**Goal:** the "intercept / repeat / replay" workflow, inside MoonMCP.

> **Licensing note.** MoonMCP will **not** bundle, download, or incorporate
> pirated or cracked commercial software (e.g. cracked Burp Suite Professional).
> That is a copyright/licence violation and off the table. The plan below uses a
> native implementation plus **legitimate** integrations only.

- **Native intercepting proxy** (stdlib `http.server` / asyncio): a local proxy
  that records request/response pairs for in-scope hosts, with a **repeater**
  (re-send a captured request with edits) and a **passive scanner** that reuses
  MoonMCP's existing header/secret/CORS/fingerprint analysers on the captured
  traffic.
- **Legitimate Burp integration** for users who own a licence: drive Burp via its
  official **REST API** / **Montoya** extension API — no cracked binaries.
- **Open-source alternatives**: optional adapters for **OWASP ZAP**, **Caido**,
  and **mitmproxy**, all of which expose supported automation APIs.

## Phase 5 — Reporting, triage & self-hosting (proposals)

- Per-program **report templates** (a program's preferred disclosure format).
- **OAST self-host** helper (stand up / point at your own interactsh) so blind
  callbacks don't depend on a third party.
- **nuclei template management** (list/select/update template sets safely).
- **OAuth / session capture** via the browser tools to feed `auth_set`.
- **Finding dedup & triage** with linkage into the existing Obsidian / graph
  export, so repeat findings collapse and the graph stays clean.

---

## Non-negotiables (every phase)

- **Authorised testing only.** The scope guard and SSRF guard are never
  bypassed by a feature.
- **Stdlib-first.** New capabilities keep a pure-standard-library path; optional
  dependencies only ever *improve* accuracy.
- **No pirated software, ever.** Integrations use vendor-supported or
  open-source automation APIs.
- **stdout is sacred.** It is the JSON-RPC channel; all logging goes to stderr.
