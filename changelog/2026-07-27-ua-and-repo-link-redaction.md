# Changelog — UA & Repository-Link Redaction (2026-07-27, earlier pass)

This pass closed the **User-Agent and repository-link leaks** that
fingerprinted the tool and its author. It preceded the critical/high debt pass
(documented in `2026-07-27-critical-and-high-debts.md`) and was the trigger for
the full audit.

## Summary

| # | Leak | Where | Status |
|---|---|---|---|
| 1 | UA `MoonMCP/0.1 (+https://the public repository; recon)` | `config.py` (2 places) | ✅ replaced with browser UA |
| 2 | SARIF `informationUri: https://the public repository` | `reporting.py:69` | ✅ set to `""` |
| 3 | CI badge linking the repo | `README.md:5` | ✅ removed |
| 4 | Homepage / Repository URLs | `pyproject.toml` | ✅ removed |
| 5 | `git remote origin` → `the public repository.git` | repo config | ✅ removed |
| 6 | `**Repo:** https://the repository URL` | `SKILL.md` | ✅ → `**Source:** local at ...` |
| 7 | UA `MoonMCP-OSINT/1.0` (OSINT search) | `intel/search.py:159` | ✅ browser UA |
| 8 | UA `"MoonMCP"` hardcoded in raw-socket probes | `desync.py`, `singlepacket.py`, `server.py http_behavior` | ✅ thread `settings.user_agent` |
| 9 | Chunk-ext payload `0;moonmcp=1` | `desync.py` | ✅ → `0;probe=1` |
| 10 | WS canary `MoonMCP-ws-probe-7f3a` | `websocket.py:341` | ✅ → `ws-probe-7f3a-echo` |
| 11 | `MOONMCP_USER_AGENT` not in launcher | `scripts/moonmcp-launch.sh` | ✅ added + exported |
| 12 | `MOONMCP_USER_AGENT` not in opencode env | `opencode.jsonc` | ✅ added |

## The UA string (before → after)

**Before** (in every recon request):
```
MoonMCP/0.1 (+https://the public repository; recon)
```

**After** (browser-like, no tool name, no repo link):
```
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
```

The default is overridable via `MOONMCP_USER_AGENT` (env var, launcher,
opencode.jsonc) for a program-specific UA, or via `program_add user_agent=...`
for a per-program UA.

## Raw-socket probes — config threading

`desync.py`, `singlepacket.py`, and `server.py http_behavior` built HTTP
requests by hand (raw sockets) and hardcoded `"User-Agent: MoonMCP"` —
bypassing `settings.user_agent` entirely. This is the bug that fingerprinted
the tool even when the operator set a custom UA.

Fixed by threading `user_agent` as a parameter from `get_context().settings.user_agent`
through `probe_desync`, `probe_modern_desync`, `build_request`, and the
`http_behavior` tool. Default fallback (`_DEFAULT_UA`) is the same browser UA.

## Test impact

`test_desync_modern.py` updated for the chunk-ext token change
(`0;moonmcp=1` → `0;probe=1`). All 45 tests in the focused suite passed:
`test_desync_modern`, `test_programs`, `test_reporting`, `test_batch_export`,
`test_sqli_lanes`, `test_stacks`.

## What remained (fixed in the later pass)

- `"MoonMCP"` as the SARIF `driver.name` and report header — made configurable
  via `MOONMCP_TOOL_NAME` in the critical/high debt pass.
- The 7 audit bugs (SSRF, CRLF, RCE-primitive consent, XML DoS, DoH injection,
  auth CRLF) — fixed in the critical/high debt pass.
- TLS/HTTP fingerprint — opt-in curl_cffi transport added in the critical/high
  debt pass.