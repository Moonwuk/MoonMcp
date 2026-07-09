# Changelog

All notable changes to MoonMCP are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

### Added
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
