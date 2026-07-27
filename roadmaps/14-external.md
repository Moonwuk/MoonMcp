# Roadmap — Layer 14: External

**Scope:** the integration with external security CLIs — detection, safe
invocation, and the nuclei coverage map. A bug here is either a scope-gating
gap, a memory-exhaustion vector, or an argument-injection path.

**Modules:** `external/cli.py`, `external/nuclei.py`, `external/__init__.py
(~517 lines).

**Status as of 2026-07-27:** no fixes in this layer yet.

---

## Module: `external/cli.py` (267 lines) — detect + invoke external CLIs

No `shell=True` (`asyncio.create_subprocess_exec` with arg list), Python-shim
collision detection (httpx/gau), timeout + zombie reaping, graceful fallback to
native tools, `_reject_dangerous_scanner_args` blocks file-I/O flags. Strong
shell-injection hygiene.

**EX1 (MEDIUM):** `run_tool` has no independent scope check — scope gating lives
in `server.py`'s `run_scanner`, not here. If `run_tool` were called directly
(bypassing `run_scanner`), no scope enforcement. Defense-in-depth gap — the
subprocess layer should be scope-aware. **EX2 (LOW):** unbounded stdout/stderr
capture — a scanner dumping gigabytes could exhaust memory. **EX3 (LOW):**
`_reject_dangerous_scanner_args` `file://` gap — `://` URLs are skipped, so
`file:///etc/passwd` bypasses the file-flag check (caught by scope in practice).
**EX4 (LOW):** TOCTOU on `tool_path` — `shutil.which` resolves at detect time,
binary invoked at run time; a PATH swap between could substitute a malicious
binary.

## Module: `external/nuclei.py` (243 lines) — coverage map + tag selector

Honest executable coverage split (delegate commodity to nuclei, keep
stateful/differential native), `build_args` uses arg list (no shell),
`normalize_finding` truncates description. Strengths.

**EX5 (LOW):** `build_args` trusts caller `url` verbatim — no URL validation
(scope check happens in `vuln_scan`, not here). **EX6 (LOW):** `normalize_finding`
ignores nuclei `info.cvss` — missed enrichment.

## Module: `external/__init__.py` (7 lines)

Clean package marker. No findings.

---

## External layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| EX1 | cli | run_tool no independent scope check — defense-in-depth gap | MEDIUM | S |
| EX2 | cli | unbounded stdout/stderr capture — memory exhaustion | LOW | S |
| EX3 | cli | file:// URI bypasses file-flag check | LOW | S |
| EX4 | cli | TOCTOU on tool_path (which → exec gap) | LOW | S |
| EX5 | nuclei | build_args trusts caller url verbatim — no validation | LOW | S |
| EX6 | nuclei | normalize_finding ignores nuclei info.cvss | LOW | S |

---

## Recommended next actions (this layer)

1. **EX1 (scope check in run_tool)** — add a `scope_check` param to `run_tool`
   and assert the target before subprocess spawn. Defense-in-depth. ~15 min.
2. **EX2 (output cap)** — stream stdout/stderr to a bounded buffer; truncate
   beyond a cap. ~15 min.

The rest are LOW — batch.

---

## Verification

```bash
python3 -c "from moonmcp.external import cli, nuclei; print('OK')"
python3 -m pytest tests/test_external*.py tests/test_nuclei*.py -q
```