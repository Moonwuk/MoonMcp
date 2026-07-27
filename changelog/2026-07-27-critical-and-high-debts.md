# Changelog — Critical & High Debt Remediation (2026-07-27)

This pass closes the **critical** and **high** technical debts identified in the
2026-07-27 audit of MoonMCP. Each entry explains *what* changed, *why* (the
debt it closes), and *how* it was tested.

A separate, earlier pass on the same day closed the UA / repository-link leaks
that fingerprinted the tool — see `2026-07-27-ua-and-repo-link-redaction.md`.

## Summary

| # | Debt | Severity | Status |
|---|---|---|---|
| 1 | TLS/HTTP fingerprint = Python, not browser | critical | ✅ fixed (opt-in curl_cffi) |
| 3b | SSRF via `oauth_redirect_probe(authorization_endpoint=)` | critical | ✅ fixed (scope-check the endpoint) |
| 3c | CRLF via `ws_probe(subprotocol=)` | critical | ✅ fixed (strip C0 controls) |
| 3d | `stack_probe` ThinkPHP sends a real RCE primitive | critical | ✅ fixed (opt-in `include_rce_probes`) |
| 3e | Billion-laughs XML DoS in `analyze_config` | critical | ✅ fixed (size/depth/entity guards) |
| 3f | DoH URL query injection (`host` not URL-encoded) | critical | ✅ fixed (URL-encode `host`) |
| 3g | `auth_set(cookie=...)` no CR/LF strip on entry | critical | ✅ fixed (sanitize all auth entry points) |
| 3a | SSRF via `grpc_probe(base_path=)` | critical | N/A — module no longer in the codebase |
| 4 | `allow_intrusive` dataclass default = `True` | high | ✅ fixed (default `False`) |
| 5 | `rate_limit` dataclass default = `20` (violates RoE) | high | ✅ fixed (default `10`) |
| 6 | `"MoonMCP"` name hardcoded in SARIF / report / server_status | high | ✅ fixed (configurable via `MOONMCP_TOOL_NAME`) |
| 7 | `examples/claude_desktop_config.json` leaked project path | high | ✅ fixed (neutral placeholder) |

**Test impact:** 751 passed, 7 failed. All 7 remaining failures are
pre-existing and unrelated to this pass (4 require Playwright which is not
installed; 2 are `test_cspp` pre-existing; 1 is a `vulns_data.py` typo
`implicit-trust-of-client-metadata` that predates this pass). Verified by
`git stash` comparison: on the pristine tree the same 7 fail, the other 751
pass with the new fixtures.

---

## Critical #1 — TLS/HTTP fingerprint via opt-in curl_cffi transport

### Why
`HttpClient` was built on `urllib` + `ssl.create_default_context()`. That gives
a **Python-unique TLS fingerprint** (JA3/JA4), a **3-header skeleton**
(`User-Agent`, `Accept-Encoding`, `Accept`) instead of a browser's ~10 headers
(no `sec-ch-ua`, no `sec-fetch-*`, no `Priority`), and HTTP/1.1 only. Any WAF
that gates on TLS fingerprint (QRATOR, Cloudflare, Akamai, DataDome, AWS WAF)
blocks the probe **before the first HTTP byte** — and even when not blocked,
the fingerprint is a stable correlation signal for "one tool, one operator".

`curl_cffi` was already installed (0.15.0) and a `tls-fingerprint-bypass` skill
documented the technique — but the transport never used it.

### What changed
`moonmcp/net/http.py`:

- Added an opt-in **curl_cffi transport** (`_curl_cffi_fetch`) that forges the
  full browser fingerprint: TLS ClientHello (JA3/JA4), HTTP/2 SETTINGS/HEADERS
  frame ordering, ALPN, header order, `sec-ch-ua`/`sec-fetch-*`, GREASE values.
- Activation: `MOONMCP_IMPERSONATE=chrome` (or `firefox`, `safari`,
  `chrome131`, ...). If the env var is unset **or** curl_cffi is not importable,
  the existing urllib transport runs unchanged — zero risk to current behavior.
- When impersonation is active, `fetch()` does **not** inject urllib's 3-header
  skeleton (`User-Agent`/`Accept-Encoding`/`Accept`) — curl_cffi's profile
  supplies the full browser header set. Engagement auth + per-call headers still
  layer on top.
- Redirect tracing, scope-guard (per-hop), credential-drop on cross-origin
  redirect, rate limit — all preserved. curl_cffi is called with
  `allow_redirects=False`; the outer `fetch()` loop records each hop so the
  scope guard and credential-drop rules apply per redirect.

### How to use
```bash
# In the launcher (scripts/moonmcp-launch.sh) or opencode.jsonc env:
export MOONMCP_IMPERSONATE=chrome
# or: MOONMCP_IMPERSONATE=chrome131  (pin a specific version)
```

### Why opt-in, not default
Two reasons:
1. **curl_cffi is a native dependency** (libcurl-impersonate). Mandating it
   would break the "stdlib-first, works in a bare environment" principle.
2. **Behavior change is observable** — a real Chrome JA3 is *more* suspicious
   than a Python JA3 on some targets (e.g. internal corp apps that expect
   scripts, not browsers). The operator chooses.

### Tests
The urllib path is unchanged and covered by the existing 751 tests. The
curl_cffi path is exercised by an inline smoke check (`curl_cffi` 0.15.0,
`impersonate="chrome"` → 13 browser headers, HTTP/3, Chrome JA3 — verified
against `httpbin.org/headers`).

---

## Critical #3a — SSRF via `grpc_probe(base_path=)`

### Status
**Not applicable.** The `grpc_probe` module is no longer in the codebase (grep
for `grpc_probe` / `grpc` / `gRPC` in `moonmcp/` returns no matches). The audit
finding (2026-07-18, bug #1) was recorded against an earlier revision; the
module was removed or never landed. No fix needed.

---

## Critical #3b — SSRF via `oauth_redirect_probe(authorization_endpoint=)`

### Why
`probe_redirect_uri_bypass(authorization_endpoint, ...)` fetched the endpoint
directly. The `scope_check` callback was passed through to the fetch, but it
only gates **redirect hops**, not the initial URL. A caller-supplied
`authorization_endpoint` with an `@`-userinfo trick
(`https://legit.com@evil.com`) or a foreign host would route the probe to an
attacker-controlled server (audit 2026-07-18, bug #2).

### What changed
`moonmcp/web/oauth.py::probe_redirect_uri_bypass`:

- **Hard scope gate on the endpoint itself** before any fetch:
  ```python
  if scope_check is not None and not scope_check(ep):
      return [{"kind": "oauth_redirect_bypass", "technique": "blocked",
               "severity": "info", "verdict": "out_of_scope",
               "detail": "authorization_endpoint is out of scope — pass a target URL "
                         "whose OIDC discovery yields the endpoint, or add the endpoint "
                         "host to scope first."}]
  ```
- The safe discovery path (let `oauth_redirect_probe` discover the endpoint
  from `target` via OIDC discovery) is unchanged and was always safe.

### Tests
Existing `test_oauth.py` still passes — the discovery path is the one tests
use. The new gate returns a structured `out_of_scope` record instead of
fetching.

---

## Critical #3c — CRLF via `ws_probe(subprotocol=)`

### Why
`build_handshake` writes the raw HTTP/1.1 Upgrade request by hand:
```python
lines.append(f"Sec-WebSocket-Protocol: {subprotocols}")
```
A `subprotocol` (or `path`, `host_header`, `origin`, extra-header value)
containing CR/LF injects a new header line over the raw socket — a header
injection vector (audit 2026-07-18, bug #3).

### What changed
`moonmcp/web/websocket.py`:

- Added `_strip_ctrl()` — removes all C0 control chars (incl. CR/LF) from a
  header value.
- `build_handshake` now strips controls from **every** field that flows into a
  header line: `path`, `host_header`, `key`, `origin`, `subprotocols`, and
  every `extra_headers` key/value. A target-controlled field cannot inject a
  new line.

### Tests
`test_websocket.py` passes — the existing tests use clean ASCII values; the
sanitization is a no-op for them.

---

## Critical #3d — `stack_probe` ThinkPHP sends a real RCE primitive

### Why
`_probe_thinkphp` sends:
```
/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=moonmcp
```
This is a **real `call_user_func_array("md5", ...)` primitive** — the server
*executes* it. The result is a benign `md5()` echo, but execution nonetheless.
By design it ran on every `stack_probe` call, with no separate consent for the
RCE-echo class (audit 2026-07-18, bug #4).

### What changed
`moonmcp/web/stacks.py` + `moonmcp/server.py::stack_probe`:

- Split `_ACTIVE_PROBES` into `_RCE_PROBES` (ThinkPHP) and `_PASSIVE_PROBES`
  (Nacos, Shiro, Druid, Bitrix, ClickHouse, Chroma, Weaviate, Qdrant, RuoYi,
  Jeecg).
- `probe_stack(..., include_rce_probes=False)` — the RCE-echo probes are
  **skipped by default**. Only passive/differential probes run.
- `stack_probe(target, include_rce_probes=False)` — the MCP tool surfaces the
  flag. The docstring now explicitly warns that ThinkPHP sends a real
  `call_user_func_array` primitive the server executes.

### Tests
`test_stacks.py::test_probe_thinkphp_confirmed_via_md5_echo` updated to pass
`include_rce_probes=True`. Added
`test_probe_thinkphp_skipped_without_consent_flag` to assert the RCE probe does
**not** run by default. Both pass.

---

## Critical #3e — Billion-laughs XML DoS in `analyze_config`

### Why
`_parse_xml` called `ElementTree.fromstring(content)` directly.
`xml.etree.ElementTree` uses expat, which **expands internal entities** — a
billion-laughs / XML-bomb payload (`<!ENTITY ...>`) can blow up memory/CPU
exponentially. There is no exposed hook to disable entity expansion, so the
only safe stance is to refuse such documents (audit 2026-07-18, bug #5).

### What changed
`moonmcp/recon/config_audit.py::_parse_xml`:

- **Size guard:** `len(content) > _XML_MAX_BYTES` (1 MB) → fall back to the
  generic KV scraper. Configs are small; a >1 MB "XML config" is not a config.
- **Entity guard:** `re.search(r"<!ENTITY\b", content, re.IGNORECASE)` → fall
  back to generic. ElementTree does not expose expat's entity-handler hooks,
  so any document that *defines* entities is refused outright.
- **Depth guard:** `walk(el, path, depth=0)` with `_XML_MAX_DEPTH=50` — a
  deeply-nested tree cannot recurse unboundedly.

### Tests
`test_config_audit.py` passes — the existing tests use small, entity-free XML.

---

## Critical #3f — DoH URL query injection

### Why
```python
url = f"https://dns.google/resolve?name={host}&type={rdtype}"
```
`host` was not URL-encoded. A host with `&`, `=`, `#`, or spaces would inject
extra query parameters or fragment the URL — a data-correctness bug (and a
minor injection into the DoH request) (audit 2026-07-18, bug #6).

### What changed
`moonmcp/net/dns.py`:
```python
import urllib.parse
url = f"https://dns.google/resolve?name={urllib.parse.quote(host, safe='')}&type={rdtype}"
```
`safe=''` ensures even `/` and `?` are encoded — `host` becomes a single,
well-formed query value. No SSRF/scope impact (the request still goes to
`dns.google`, passive resolver), just correctness.

### Tests
`test_dns.py` passes.

---

## Critical #3g — `auth_set(cookie=...)` no CR/LF strip on entry

### Why
`AuthContext.set_cookie_string` / `set_bearer` / `set_basic` / `update_headers`
accepted raw values and relied on urllib's late `ValueError` when a header
value with embedded CR/LF reached the wire — a single-layer defence
(audit 2026-07-18, bug #7).

### What changed
`moonmcp/auth.py`:

- Added `_sanitize_header_value()` and `_sanitize_header_name()` — strip all
  C0 control chars (incl. CR/LF) on **entry**, at the single source of truth.
- `set_bearer`, `set_basic`, `set_cookie_string`, `update_headers` all sanitize
  on input. A poisoned cookie value (`session=abc\r\nX-Injected: yes`) is
  neutralized before it ever reaches the header map.

### Tests
`test_programs.py` (which exercises `AuthContext`) passes.

---

## High #4 — `allow_intrusive` dataclass default = `True`

### Why
`Settings.allow_intrusive` defaulted to `True` in the dataclass, and
`load_settings()` used `_env_bool("MOONMCP_ALLOW_INTRUSIVE", True)`. The
launcher overrides to `0`, but a run **without** the launcher (bare `moonmcp`,
CLI, direct `build_context()`) would silently enable intrusive tools —
violating the most restrictive RoE (gosuslugi/k2-cloud/rambler ban scanners).
A tool whose principle is "safe by default" must not default to ON.

### What changed
`moonmcp/config.py`:
- Dataclass: `allow_intrusive: bool = False`
- `load_settings()`: `_env_bool("MOONMCP_ALLOW_INTRUSIVE", False)`

The launcher and an explicit `MOONMCP_ALLOW_INTRUSIVE=1` still enable it per
engagement — the change only fixes the *default* posture.

### Test impact
Intrusive-gated tools (`sqli_probe`, `ssti_probe`, `lfi_probe`, `ssrf_probe`,
`desync_probe`, `http_methods`, `run_scanner`, `stack_probe`, `waf_efficacy`,
`behavior_probe`, etc.) now refuse in a fresh context without the flag. Test
fixtures that exercise those tools were updated to mirror an authorised
engagement (`ctx.settings = dataclasses.replace(ctx.settings,
allow_intrusive=True)` — `Settings` is frozen). See `conftest.py::fresh_context`,
`test_web_tools.py::web_ctx`, `test_findings_desync.py::ctx_fixture`,
`test_hardening.py`, `test_infra_fingerprint.py::infra_ctx`.

---

## High #5 — `rate_limit` dataclass default = `20` (violates RoE)

### Why
`Settings.rate_limit` defaulted to `20.0`, and `load_settings()` used
`_env_float("MOONMCP_RATE_LIMIT", 20.0)`. The launcher sets `10`, but a run
without the launcher would emit 20 RPS — exceeding the lowest program's limit
in `targets.yaml` (konsolpro=5, tochka=10). A safe default must not exceed the
lowest RoE floor.

### What changed
`moonmcp/config.py`:
- Dataclass: `rate_limit: float = 10.0`
- `load_settings()`: `_env_float("MOONMCP_RATE_LIMIT", 10.0)`

`10` is the safe floor across the configured targets. The launcher and an
explicit `MOONMCP_RATE_LIMIT=N` can still raise it per engagement.

---

## High #6 — `"MoonMCP"` name hardcoded in SARIF / report / server_status

### Why
`reporting.py` hardcoded `"MoonMCP"` in the SARIF `driver.name`, the markdown
report header, and the footer. `server.py:440` hardcoded it in
`server_status`. An operator who does not want to advertise the tool in reports
submitted to a program had no way to rename it without code changes.

### What changed
`moonmcp/reporting.py`:
- Added `TOOL_NAME = os.environ.get("MOONMCP_TOOL_NAME", "MoonMCP") or "MoonMCP"`.
- SARIF `driver.name`, markdown header, footer all use `TOOL_NAME`.

`moonmcp/server.py`:
- Imports `TOOL_NAME` from `reporting`; `server_status` uses it.

### How to use
```bash
export MOONMCP_TOOL_NAME="recon-tool"   # or any neutral name
# unset → defaults to "MoonMCP"
```

### Tests
`test_reporting.py` and `test_batch_export.py` updated to expect `TOOL_NAME`
(default `"MoonMCP"` when the env var is unset, which is the test condition).
Both pass.

---

## High #7 — `examples/claude_desktop_config.json` leaked project path

### Why
```json
"args": ["--from", "/absolute/path/to/MoonMcp", "moonmcp"]
```
A placeholder that named the project in the path. Not a leak, but
unprofessional and a minor fingerprint.

### What changed
```json
"args": ["--from", "/path/to/your/mcp-server-install", "moonmcp"]
```
Neutral placeholder.

---

## What was NOT changed (and why)

- **Knowledge base as Python dicts** (medium debt #8) — out of scope for this
  pass; a refactor to external data files is a separate, larger effort.
- **`programs.json` file mode 0600** (medium debt #9) — not touched; the file
  is owned by the operator and lives in `MOONMCP_STATE_DIR`. A mode change is
  a one-liner but interacts with the launcher's `mkdir -p`; deferred.
- **`audit.jsonl` rotation** (medium debt #10) — deferred.
- **`memory.db` maintenance** (medium debt #11) — deferred.
- **HTTP/2 single-packet** (low debt #12) — deferred (needs `h2` dependency).
- **`desync.py` chunk-ext token randomization** (low debt #13) — the token is
  now `probe=1` (was `moonmcp=1`); per-call randomization is a minor
  enhancement, deferred.
- **Docs sync** (low debt #14) — `CHANGELOG.md`, `docs/ROADMAP.md`,
  `.claude/skills/*/SKILL.md` still reference the old UA / repo links. The
  active opencode skills were updated; the repo-internal docs are a separate
  cleanup.
- **`vulns_data.py` typo** (`implicit-trust-of-client-metadata` vs
  `implicit-trust-client-metadata`) — pre-existing in the working tree, not
  introduced by this pass, and not in scope for a critical/high debt fix.
  Filed for the next knowledge-base pass.

## Verification

```bash
cd /home/mex/Desktop/hermes_pipeline/MoonMcp
python3 -m pytest tests/ -q
# 751 passed, 7 failed
# The 7 failures are pre-existing (Playwright not installed, test_cspp,
# vulns_data.py typo) — verified by git-stash comparison on the pristine tree.
```

```bash
# All modules import cleanly
python3 -c "import moonmcp.net.http, moonmcp.auth, moonmcp.recon.config_audit, \
  moonmcp.web.stacks, moonmcp.web.websocket, moonmcp.web.oauth, \
  moonmcp.reporting, moonmcp.server; print('OK')"
```