# Roadmap — Layer 15: Server

**Scope:** the MCP server itself — 6117 lines, 169 tools, the `get_context`
singleton, the `_require_scope` choke point, the `@active_tool`/`@safe_tool`
decorators, and the tool/prompts/resources registration. A bug here is either
a maintainability problem (the monolith), a singleton/testability issue, an
error-envelope leak, or a missing audit trail.

**Module:** `server.py` (6117 lines, 169 tools, 11 resources, 9 prompts).

**Status as of 2026-07-27:** the `TOOL_NAME` import was added (server_status
uses it). This roadmap covers what remains.

---

## Headline findings

**SV1 (HIGH): the monolith.** 6117 lines, 169 tools, 60+ imports in one file.
Unmaintainable, hard to test in isolation, merge-conflict-prone. Should be
split by tool family: `server/meta_scope.py`, `server/passive.py`,
`server/active_light.py`, `server/active_intrusive.py`,
`server/injection_probes.py`, `server/knowledge_tools.py`,
`server/reporting_tools.py`, `server/external_tools.py`,
`server/interception.py`, `server/prompts_resources.py`. The `@mcp.tool`
registration can be split across modules as long as they share the one `mcp`
FastMCP instance.

**SV2 (MEDIUM): `get_context()` module-global singleton.** `_CTX` is process-
wide, lazily built. Not injectable (testing requires monkeypatching), no per-
session isolation in multi-session deployments, env-var changes after first
call are ignored. A DI container (or a `contextvars.ContextVar`) would be
cleaner and testable.

**SV5 (MEDIUM): `add_finding` not audited.** Recording findings (which contain
evidence/PII) into the session store is not logged via `ctx.audit.record`.
Only `export_obsidian`, `oast_selfhost`, scope checks, and external tools are
audited (8 `audit.record` calls total). The evidentiary trail has a gap at the
most evidence-bearing operation.

---

## Strengths (the architecture is sound)

- **Single scope choke-point** (`_require_scope`: intrusive gate + scope check
  + resolve-then-check SSRF guard + audit). Every packet-sending tool routes
  through it.
- **`@active_tool` decorator** auto-gates every packet-sending tool via a
  `__moonmcp_gated__` flag — verifiable by the guard test.
- **`self_scoped=True` pattern** for multi-target tools (`http_repeater`,
  `intruder`, `firebase_exposure`, `parse_openapi`, `confirm_finding`,
  `probe_batch`, `run_scanner`, `workflow_probe`, `second_order_sqli_probe`)
  — each calls `_require_scope` explicitly per target.
- **`safe_tool` structured-error envelope** — tools return `{error: ...}`
  instead of raising into the MCP transport.
- **`_reject_dangerous_scanner_args`** blocks file-I/O flags on external
  scanners.
- **Resolve-then-check SSRF guard** runs off-event-loop via `asyncio.to_thread`.

The choke-point design is the strongest part of the tool. The findings below
are about the *container* (the file), not the *contract* (the gating).

---

## Server layer — prioritized backlog

| ID | Finding | Severity | Effort |
|----|---------|----------|--------|
| SV1 | monolith — 6117 lines / 169 tools / 60+ imports in one file | HIGH | L |
| SV2 | get_context() module-global singleton — not injectable, no session isolation | MEDIUM | M |
| SV3 | safe_tool leaks internal details in error envelope (type + message) | MEDIUM | S |
| SV4 | _apply_tool_profile uses mcp._tool_manager._tools private API | MEDIUM | S |
| SV5 | add_finding not audited — evidence/PII recording has no audit trail | MEDIUM | S |
| SV6 | _caller_tool() uses sys._getframe(2) — fragile stack-walk | LOW | S |
| SV7 | report and export_findings not audited | LOW | S |
| SV8 | _reject_dangerous_scanner_args single-backslash path gap | LOW | S |
| SV9 | no tool registration automation — manual decorator placement | LOW | M |

---

## Recommended next actions (this layer)

1. **SV5 (add_finding audit)** — one `ctx.audit.record("add_finding", ...)`
   call. Closes the evidentiary gap at the most evidence-bearing operation.
   ~10 min.
2. **SV3 (error envelope)** — sanitize the error string in `safe_tool` (strip
   file paths, internal hostnames). ~15 min.
3. **SV4 (private API)** — pin the FastMCP version or find a public API for
   `_apply_tool_profile`. ~30 min.
4. **SV1 (split the monolith)** — the big refactor. Do it last, after the
   layer-specific fixes, so the split carries the improvements. ~L effort but
   highest long-term leverage.
5. **SV2 (DI / contextvars)** — replace the global with a `contextvars.ContextVar`
   for testability + session isolation. ~M effort, do alongside SV1.

---

## Verification

```bash
python3 -c "from moonmcp import server; print('OK')"
# The full suite exercises the server's tool registration + scope gating.
python3 -m pytest tests/test_server_integration.py tests/test_active_tool_guard.py -q
```