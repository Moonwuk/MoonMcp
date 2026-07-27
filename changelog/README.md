# Changelog

This directory records security- and OPSEC-relevant changes to MoonMCP. Each
file is a self-contained entry for one remediation pass: what changed, why
(the debt/leak it closes), and how it was verified.

## Entries

| Date | Pass | File |
|---|---|---|
| 2026-07-27 | UA & repository-link redaction | [2026-07-27-ua-and-repo-link-redaction.md](2026-07-27-ua-and-repo-link-redaction.md) |
| 2026-07-27 | Critical & high debt remediation | [2026-07-27-critical-and-high-debts.md](2026-07-27-critical-and-high-debts.md) |
| 2026-07-27 | High-leverage fixes (scope gap, consent gates, fingerprint sweep, saml defusedxml, oast bind, KB typo, obsidian TOOL_NAME, add_finding audit) | [2026-07-27-high-leverage-fixes.md](2026-07-27-high-leverage-fixes.md) |

## 2026-07-27 — UA & repository-link redaction

Closed the User-Agent and `the public repository` link leaks that
fingerprinted the tool in every recon request and in SARIF exports. Replaced
the identifying UA with a browser-like default, threaded `settings.user_agent`
through the raw-socket probe modules (`desync`, `singlepacket`, `http_behavior`)
that had hardcoded `"MoonMCP"`, and added `MOONMCP_USER_AGENT` to the launcher
and `opencode.jsonc`.

## 2026-07-27 — Critical & high debt remediation

Closed the critical and high technical debts from the 2026-07-27 audit:

- **Critical #1** — opt-in curl_cffi transport for browser TLS/HTTP fingerprint
  (`MOONMCP_IMPERSONATE=chrome`), urllib fallback unchanged.
- **Critical #3b** — `oauth_redirect_probe` now scope-checks the
  `authorization_endpoint` before fetching (closes the `@`-userinfo SSRF).
- **Critical #3c** — `ws_probe` strips C0 controls (incl. CR/LF) from
  `subprotocol` and every header field (closes the raw-socket header injection).
- **Critical #3d** — `stack_probe` ThinkPHP RCE-echo probe is now opt-in
  (`include_rce_probes=True`); passive probes run by default.
- **Critical #3e** — `analyze_config` XML parser refuses >1 MB inputs,
  `<!ENTITY>` declarations, and >50-deep nesting (closes billion-laughs DoS).
- **Critical #3f** — DoH `host` is URL-encoded in the `dns.google/resolve`
  query (closes query-parameter injection).
- **Critical #3g** — `auth_set` sanitizes C0 controls on entry at every auth
  field (bearer, basic, cookie, headers) — no longer relies on urllib's late
  ValueError.
- **High #4** — `allow_intrusive` dataclass default → `False` (was `True`);
  a run without the launcher no longer silently enables scanners.
- **High #5** — `rate_limit` dataclass default → `10` (was `20`); a run
  without the launcher no longer exceeds the lowest program's RoE floor.
- **High #6** — `"MoonMCP"` name in SARIF/report/server_status is configurable
  via `MOONMCP_TOOL_NAME`.
- **High #7** — `examples/claude_desktop_config.json` path placeholder
  neutralized.

**Test result:** 751 passed, 7 failed. All 7 remaining failures are
pre-existing and unrelated (Playwright not installed, `test_cspp`, a
`vulns_data.py` typo). Verified by `git stash` comparison.

## Conventions

- One file per pass, named `YYYY-MM-DD-<short-title>.md`.
- Lead with a summary table (debt ID, severity, status).
- For each change: **Why** (the debt), **What changed** (file + diff intent),
  **How to use** (env var / flag, if applicable), **Tests**.
- End with **What was NOT changed (and why)** — keeps the scope honest.
- Verification commands at the bottom (`pytest`, import smoke).