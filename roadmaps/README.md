# Roadmaps — MoonMCP improvement backlog

This directory holds a per-layer audit of MoonMCP: every module read, every
function understood, every finding filed with a severity and effort estimate.
The goal is a complete, prioritized picture of what's strong, what's OK, and
what to improve — and where the leverage is.

## How to read

Each `NN-layer.md` file covers one architectural layer:

- a **per-module** breakdown: purpose, key functions, strengths, findings
- a **prioritized backlog** table: `ID | Module | Finding | Severity | Effort`
- a **recommended next actions** section: the highest-leverage fixes first

**Severity:** HIGH = security bug / SSRF / scope bypass / weaponized probe /
DoS. MEDIUM = correctness, hygiene, missing concurrency/timeouts, fingerprint
leaks, trust-tag gaps. LOW = polish.
**Effort:** S = <30 min, M = 1-4 h, L = >4 h.

## Layers — all audited

| # | Layer | File | Findings |
|---|---|---|---|
| 1 | Safety core (scope, config, context, auth, programs) | [01-safety-core.md](01-safety-core.md) | 21 |
| 2 | Transport (http, dns, tls, jarm, ports, ratelimit) | [02-transport.md](02-transport.md) | 22 |
| 3 | Recon (24 modules) | [03-recon.md](03-recon.md) | 49 |
| 4 | Web injection (sqli, ssti, lfi, xxe, ssrf*, ...) | [04-web-injection.md](04-web-injection.md) | 24 |
| 5 | Web auth (oauth, saml, jwt, authz, authflow) | [05-web-auth.md](05-web-auth.md) | 19 |
| 6 | Web protocol (desync, singlepacket, websocket, ...) | [06-web-protocol.md](06-web-protocol.md) | 12 |
| 7 | Web logic / modern (graphql, fastjson, cspp, ...) | [07-web-logic-modern.md](07-web-logic-modern.md) | 22 |
| 8 | Web bypass / exposure (waf, pathnorm, stacks, probes, ...) | [08-web-bypass-exposure.md](08-web-bypass-exposure.md) | 31 |
| 9 | Web browser (browser, screenshot) | [09-web-browser.md](09-web-browser.md) | 7 |
| 10 | Intel / OSINT (search, cve, shodan, oast*, ...) | [10-intel.md](10-intel.md) | 21 |
| 11 | Knowledge (5 KB modules + data) | [11-knowledge.md](11-knowledge.md) | 18 |
| 12 | Memory / state (memory, audit, leadpipe, confirm, ...) | [12-memory-state.md](12-memory-state.md) | 22 |
| 13 | Reporting (reporting, obsidian, findings, cvss) | [13-reporting.md](13-reporting.md) | 12 |
| 14 | External (cli, nuclei) | [14-external.md](14-external.md) | 6 |
| 15 | Server (server.py, 6117 lines, 169 tools) | [15-server.md](15-server.md) | 9 |

**Total: ~275 findings across 15 layers.**

## Cross-layer themes

Some findings repeat across layers and are worth fixing once, everywhere:

### Theme A — the net-layer scope gap (8 findings)
`HttpClient.fetch(url, scope_check=...)` only applies `scope_check` to redirect
targets, not the initial URL. Five recon modules + the `oauth_redirect_probe`
SSRF (already fixed) share this root cause. **One fix in `fetch`** — scope-check
`url` before the first hop — closes all of them. See `03-recon.md`.

### Theme B — "detection vs exploitation" line (11 HIGHs)
Eleven HIGH findings are probes that do more than detect — they complete a real
state-changing action, execute an RCE primitive, exfiltrate real credentials,
or send a live exploit payload with no consent gate:

- Layer 4: WI1 (SSRF extracts cloud creds), WI3 (gopher SSRF), WI4 (Oracle
  UTL_HTTP live OOB)
- Layer 6: WP1 (methods sends real DELETE/PUT to exact URL)
- Layer 7: WL1-WL3, WL5, WL7-WL9 (logic/value/workflow probes complete real
  financial/state-changing actions)
- Layer 8: WE1/WE4 (waf gates documented but not enforced), WE18/WE19 (stacks
  passive-tier probes that are active), WE25/WE26 (probes.py exports live
  exploit primitives with no consent gate)

**One pattern fix** — a `dry_run` / `confirm_state_change` / consent flag on
every state-changing or exploit-primitive probe, same as the `stack_probe`
ThinkPHP fix from the 2026-07-27 critical/high pass. Closes all 11 with a
consistent control.

### Theme C — fingerprint leaks (15+ findings)
Tool-name strings ("MoonMCP", "moonmcp", "moon") embedded in UAs, canaries,
markers, boundaries, JSON comments, foreign Origins, Obsidian filenames, audit
records. Same class as the UA leak fixed in the first pass, spread across
Layers 6, 8, 10, 13. **One sweep** — replace every `moon*`/`Moonmcp*` literal
with neutral random strings (or `TOOL_NAME` where appropriate).

### Theme D — XML entity-expansion DoS (2 findings)
`xml.etree.ElementTree.fromstring` with no entity guard in `recon/config_audit`
(fixed 2026-07-27) and `web/saml` (WA4, still open). **One dependency**
(`defusedxml`) + entry-point size caps closes both.

### Theme E — DNS rebinding TOCTOU (Layer 1 + 2)
The SSRF guard resolves a host, then the transport re-resolves it. Pin the
resolved IP. See `01` and `02`.

### Theme F — missing rate-limit / cache / concurrency (Layer 10 + 12)
NVD/Shodan/ip-api without rate-limit or cache; SQLite without WAL; audit log
without rotation. **One batch** — a TTL-cache + backoff helper for OSINT APIs;
WAL + connection split for SQLite; a rotating handler for the audit log.

### Theme G — knowledge base maintainability (Layer 11)
~19k lines of hand-maintained Python dicts, no schema version, no validator,
no externalization. **One big refactor** — external YAML/JSON + loader + CI
schema validator. Largest long-term effort, highest long-term leverage.

## The highest-leverage single fixes (do these first)

| Fix | Closes | Effort |
|---|---|---|
| Scope-check the initial URL in `HttpClient.fetch` | 8 recon MEDIUMs + the oauth SSRF pattern | S |
| `dry_run` / consent flag on every state-changing probe | 11 HIGHs (the "detection vs exploitation" line) | M (per probe, batchable) |
| Replace every `moon*`/`Moonmcp*` literal with neutral strings | 15+ fingerprint leaks | S (one sweep) |
| `defusedxml` in `saml.py` + size caps | WA4 + WA5 + WA6 | S |
| Pin resolved IP in `fetch` (DNS rebinding) | S1 + T1 | M |
| `oast_server` default bind `127.0.0.1` + advertise-host assertion | IN1 + IN2 | S |
| Fix `vulns_data.py` typo + add FK assertion | KB8 + KB9 | S |
| `add_finding` audit + `obsidian.py` TOOL_NAME | SV5 + RP6 | S |

## Relationship to the changelog

The `changelog/` directory records what was **already fixed** (UA leaks,
critical/high debts). The `roadmaps/` directory records what **remains**. A
roadmap finding, once fixed, moves to a changelog entry.

## Status legend

- ✅ audited — module-by-module findings filed (all 15 layers)
- pending — not yet audited (none)
- N/A — layer not applicable (none)

## Verification

Each layer file ends with verification commands (imports + pytest) so the
audit is reproducible. The whole suite:

```bash
cd /home/mex/Desktop/hermes_pipeline/MoonMcp
python3 -m pytest tests/ -q   # 751 passed, 7 pre-existing failures
```

The 7 pre-existing failures are: 4 × `test_browser` (Playwright not installed),
2 × `test_cspp`, 1 × `test_vulns` (the KB8 typo — will pass once fixed).
Verified by `git stash` comparison on the pristine tree.