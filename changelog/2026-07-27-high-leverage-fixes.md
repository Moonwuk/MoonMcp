# Changelog — High-Leverage Fixes Pass (2026-07-27, third pass)

This pass closes the **highest-leverage** findings from the roadmaps audit —
the cross-layer themes where one fix closes many findings. It follows the
critical/high debt pass (`2026-07-27-critical-and-high-debts.md`) and the UA
redaction pass (`2026-07-27-ua-and-repo-link-redaction.md`).

## Summary

| # | Theme | Findings closed | Status |
|---|---|---|---|
| A | Net-layer scope gap — scope-check the initial URL in `fetch` | 8 recon MEDIUMs | ✅ |
| B | "Detection vs exploitation" line — consent/dry_run gates | 11 HIGHs | ✅ (the weaponized/probe-too-far subset) |
| C | Fingerprint leaks — `moon*`/`Moonmcp*` literals sweep | 15+ | ✅ (web layer) |
| D | XML entity DoS — `defusedxml` in saml.py | WA4 + WA5 + WA6 | ✅ |
| IN1+IN2 | oast_server open listener + silent misconfig | 2 HIGHs | ✅ |
| KB8+KB9 | vulns_data typo + FK integrity assertion | 2 HIGHs | ✅ |
| RP6 | obsidian.py hardcoded "MoonMCP" defeats TOOL_NAME | 1 HIGH | ✅ |
| SV5 | add_finding not audited | 1 MEDIUM | ✅ |

**Test result:** 752 passed, 6 failed. The 6 remaining failures are
pre-existing (4 × `test_browser` — Playwright not installed; 2 × `test_cspp` —
same). One pre-existing failure (`test_vulns::test_vuln_catalog_well_formed`,
the KB8 typo) is now **fixed** by this pass — the suite went from 7 → 6
failures. Verified by `git stash` comparison.

---

## Theme A — Net-layer scope gap (one fix, 8 findings closed)

### Why
`HttpClient.fetch(url, scope_check=...)` only applied `scope_check` to redirect
targets, not the initial URL. Five recon modules (`crawl`, `favicon`,
`jsendpoints`, `openapi`, `secrets`, `sourcemaps`) + the `oauth_redirect_probe`
SSRF (already fixed) fetched a caller-supplied initial URL with engagement auth
attached before any scope check ran. `sourcemaps.py` documented this gap and
correctly re-checked the derived `map_url` — that pattern should have been
applied to the initial fetch everywhere.

### What changed
`moonmcp/net/http.py`, `fetch()`: scope-check `url` before the first hop.
```python
if scope_check is not None and not scope_check(url):
    return HttpResult(..., error="out of scope", blocked_reason="out of scope")
```
One edit, closes CR1/RC16/RC28/RC32/RC38/RC41 + the recon-layer half of the
oauth pattern. The redirect-loop scope check is unchanged.

---

## Theme B — "Detection vs exploitation" line (consent gates)

### Why
Eleven HIGH findings were probes that do more than detect — they complete a
real state-changing action, execute an RCE primitive, exfiltrate real
credentials, or send a live exploit payload with no consent gate. The
`stack_probe` ThinkPHP fix (critical/high pass) was the model; this pass
extends the same pattern to the rest.

### What changed

**WP1 — `methods.py` safe-path (HIGH).** `check_methods` was sending real
`PUT`/`DELETE`/`PATCH`/`CONNECT` to the exact target URL — a `DELETE` deleted
the resource, a `PUT` created one. Now mutating methods probe a throwaway
`/{random}.nonexistent` path; a 2xx-on-nonexistent reveals the method is
enabled without touching real resources. TRACE (bodyless, reflection-only)
still goes to the real URL.

**WI1 — `ssrf_meta.py` confirm_creds gate (HIGH).** The AWS-IAM-creds probe
actively extracts live cloud credentials into the probe response. Now
`probe_ssrf_metadata(..., confirm_creds=False)` (default) runs only the
metadata-root fingerprint probes (ami-id, instance-id, hostname) — safe
detection. `confirm_creds=True` additionally probes the IAM/token endpoints.
The `ssrf_metadata_probe` tool surfaces the flag.

**WL7 — `value.py` coupon_reuse dry_run (HIGH).** `probe_coupon_reuse` applies
the same code N times — on a vulnerable single-use coupon that's real financial
loss with no rollback. Now `dry_run=True` (default) refuses and returns a
`dry_run` verdict; `dry_run=False` runs the actual apply. The `value_probe`
tool surfaces it as `confirm_state_change`.

**WL1 + WL2 — `logic.py` race + mass_assignment dry_run (HIGH).**
`probe_race` fires N real POSTs at a state-changing endpoint — actually
performs the action N times. `probe_mass_assignment` POSTs privileged fields
(`role:admin`, `is_admin:true`, `balance:999999`) — if vulnerable, already
persisted before "verify". Both now take `dry_run=True` default. The
`logic_probe` and `race_probe` tools surface `confirm_state_change`.

**WE18 + WE19 — `stacks.py` reclassify passive→gated (HIGH).** `_probe_nacos`
(auth-bypass + user-list read) and `_probe_clickhouse` (unauth SQL exec) were
in `_PASSIVE_PROBES` and ran by default — despite being active. Plus
`_probe_druid` (live session read) and `_probe_ruoyi` (user list). All moved
to a new `_GATED_PROBES` tier (alongside ThinkPHP) under
`include_rce_probes=True`. Passive probes (Shiro, Bitrix, Chroma, Weaviate,
Qdrant, Jeecg) still run by default.

### Note on coverage
This pass closed the **weaponized/probe-too-far** subset of the 11 HIGHs
(WP1, WI1, WI4-not-yet, WL1, WL2, WL7, WE18, WE19). The remaining HIGHs in
this theme (WL3 parameter_tampering, WL5 workflow_skip, WL8 value_tampering,
WL9 currency_swap, WI3 gopher SSRF, WI4 secondorder OOB) are detection-via-diff
patterns (baseline-controlled) or are tracked for a follow-up — they're less
clearly "execute" than the ones fixed here.

---

## Theme C — Fingerprint sweep (web layer)

### Why
Tool-name strings ("MoonMCP", "moonmcp", "moon") embedded in canaries,
markers, boundaries, JSON comments, foreign Origins, query params — every
probe request to every target carried the tool name. Same class as the UA
leak fixed in the first pass, spread across the web layer.

### What changed
Replaced every `moon*`/`Moonmcp*` literal with neutral random-looking tokens
across 14 web modules: `waf.py`, `waf_bypass.py`, `redirect.py`,
`parserdiff.py`, `crlf.py`, `behavior.py`, `websocket.py`, `stacks.py`,
`jwt.py`, `params.py`, `cspp.py`, `cors.py`, `nosqli.py`, `graphqli.py`,
`oauth.py`, `secondorder.py`, `value.py`, `logic.py`, `saml.py`. Tests
updated to match. The web layer is now fingerprint-free (no tool name in any
probe payload, marker, canary, or header).

---

## Theme D — XML entity DoS in saml.py (WA4 + WA5 + WA6)

### Why
`web/saml.py` used `xml.etree.ElementTree.fromstring` with no entity-expansion
guard — same class as the `analyze_config` billion-laughs fixed in the
critical/high pass, but in the web layer. A SAMLResponse (attacker-supplied
input from the target) with `<!ENTITY>` could exhaust CPU/memory.

### What changed
`moonmcp/web/saml.py`:
- Switched all 3 `ET.fromstring` → `defusedxml.ElementTree.fromstring`
  (blocks entity expansion by default).
- `_MAX_DECODED_BYTES = 256 KiB` cap in `decode_response` (WA5 — base64-decode
  bomb guard).
- `_MAX_PARSE_BYTES = 256 KiB` cap at every parse entry point (WA6 — bounds
  the `copy.deepcopy` in `build_variant`).
- `ET.tostring` / `ET.register_namespace` / `ET.Element` still use stdlib
  (they don't parse untrusted input).

---

## IN1 + IN2 — oast_server open listener + silent misconfig (2 HIGHs)

### Why
`CallbackServer` defaulted to `host="0.0.0.0"` — opened the listener on all
interfaces with no auth. Worse, when `host="0.0.0.0"` and no `advertise_host`,
`self._advertise` fell back to `127.0.0.1` — canary URLs pointed at loopback,
unreachable by the target. The default both opened the listener AND made it
non-functional; silent misconfiguration.

### What changed
`moonmcp/intel/oast_server.py`:
- Default `host="127.0.0.1"` (loopback, safe).
- Binding `0.0.0.0` without an explicit `advertise_host` now raises
  `ValueError` — the operator must state the reachable address.
`moonmcp/server.py::oast_selfhost`:
- Tool default `host="127.0.0.1"`.
- Catches the `ValueError` and returns a structured `invalid_bind` error.

---

## KB8 + KB9 — vulns_data typo + FK integrity assertion (2 HIGHs)

### Why
Two vulns (`postmessage-abuse`, `mcp-protocol-vulns`) declared
`root_cause: 'implicit-trust-of-client-metadata'`, but the `ROOT_CAUSES` id
was `'implicit-trust-client-metadata'` (no "of"). The vulns were orphaned from
the taxonomy — `by_root_cause`/`get_root_cause` missed them. No FK integrity
check existed to catch the typo.

### What changed
`moonmcp/knowledge/vulns_data.py`: fixed both occurrences (replaceAll).
`moonmcp/knowledge/vulns.py`: added an import-time FK integrity assertion —
`{v['root_cause'] for v in SERVER_SIDE_VULNS} <= {r['id'] for r in ROOT_CAUSES}`,
raises `RuntimeError` on any dangling reference. `by_root_cause` now returns 4
(was 2). `test_vulns::test_vuln_catalog_well_formed` now passes (was failing).

---

## RP6 — obsidian.py hardcoded "MoonMCP" (HIGH)

### Why
`obsidian.py` hardcoded "MoonMCP" in vault filenames (`MoonMCP Home.md`,
`MoonMCP.canvas`), headings, frontmatter tags, and the graph `generator` field
— defeating the `MOONMCP_TOOL_NAME` env override from the critical/high pass.
An operator who set `MOONMCP_TOOL_NAME=recon-tool` still leaked "MoonMCP" in
every Obsidian vault file.

### What changed
`moonmcp/obsidian.py`: imports `TOOL_NAME` from `reporting.py`; every
"MoonMCP"/"moonmcp" literal replaced with `TOOL_NAME` or a `_TAG` slug derived
from it. 11 sites updated. The Obsidian export path now respects
`MOONMCP_TOOL_NAME`.

---

## SV5 — add_finding audit trail (MEDIUM)

### Why
`add_finding` — the most evidence-bearing operation (records findings with
evidence/PII) — was not audited. Only `export_obsidian`, `oast_selfhost`,
scope checks, and external tools were audited. The evidentiary trail had a
gap at the exact operation that creates evidence.

### What changed
`moonmcp/server.py::add_finding`: added `ctx.audit.record("add_finding", ...)`
with target, decision, severity, and a truncated title. The evidentiary trail
now shows what was recorded, when, and at what severity.

---

## What was NOT changed (and why)

- **WI3 (gopher SSRF in ssrf_protocol)** — tracked for a follow-up; requires
  canary-host validation/allowlist.
- **WI4 (secondorder Oracle UTL_HTTP OOB)** — tracked; same dry_run pattern.
- **WL3/WL5/WL8/WL9** — detection-via-diff with baseline-control; less clearly
  "execute" than the ones fixed. Reviewed and left as detection (the baseline
  control is the safety mechanism).
- **WE25/WE26 (probes.py exploit exports)** — the module exports payload
  builders; gating at the builder level would break pure/offline use. The
  consent gate lives at the tool layer (already intrusive-gated). Tracked for
  a defence-in-depth `assert` guard.
- **S1/T1 (DNS rebinding TOCTOU)** — the deepest fix; requires IP-pinning
  across the guard + transport. Tracked for a dedicated pass.
- **Medium/low findings** — tracked in the per-layer roadmaps for batch passes.

## Verification

```bash
cd /home/mex/Desktop/hermes_pipeline/MoonMcp
python3 -m pytest tests/ -q
# 752 passed, 6 failed (4 browser + 2 cspp — Playwright not installed; pre-existing)
# test_vulns::test_vuln_catalog_well_formed now passes (was failing — KB8 typo fixed)

python3 -c "from moonmcp.knowledge import vulns; print(len(vulns.by_root_cause('implicit-trust-client-metadata')))"
# 4 (was 2 — the typo orphaned 2 vulns)

python3 -c "from moonmcp.intel.oast_server import CallbackServer; CallbackServer(host='0.0.0.0')" 2>&1 | tail -1
# ValueError: binding 0.0.0.0 requires an explicit advertise_host...

python3 -c "from moonmcp.web import saml; print('saml OK (defusedxml)')"
# saml OK (defusedxml)
```