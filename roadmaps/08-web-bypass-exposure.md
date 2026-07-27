# Roadmap — Layer 8: Web Bypass / Exposure

**Scope:** the WAF/bypass, path-normalization, redirect, debug-panel, exposure,
stack-fingerprint, generic-probe, and behavior modules. A bug here is either a
probe that sends a real exploit primitive with no consent gate, a documented
safety control that isn't enforced, a passive-tier probe that's actually
active, or a fingerprint leak.

**Modules:** `waf.py`, `waf_bypass.py`, `pathnorm.py`, `redirect.py`,
`debugpanel.py`, `exposure.py`, `stacks.py`, `probes.py`, `behavior.py
(~1218 lines, browser.py is in Layer 9).

**Status as of 2026-07-27:** the `stacks.py` ThinkPHP RCE opt-in fix is
**verified present** (`_RCE_PROBES` excluded from `_PASSIVE_PROBES`,
`include_rce_probes=False` default). This roadmap covers what remains — and
the audit found that the ThinkPHP fix, while correct, only addressed **one** of
several misclassified active probes in `stacks.py`.

---

## Headline findings

**Seven HIGH** — the largest cluster of any layer. Three patterns:

### Pattern 1 — Documented safety control not enforced (WE4, WE1)
`waf_bypass.py` docstring claims `MOONMCP_ALLOW_INTRUSIVE` gate, but
`test_waf_efficacy` only takes `scope_check` — **the gate is documented but
does not exist in code**. `waf.py`'s `active=True` default sends real
SQLi/XSS/LFI strings with no intrusive gate. Any caller gets the full attack-
payload sweep. This is the most serious finding: a safety control that's
advertised but missing.

### Pattern 2 — Passive-tier probes that are actually active (WE18, WE19, WE20, WE21)
The `stacks.py` opt-in fix moved **ThinkPHP** to `_RCE_PROBES`. But three other
probes stayed in `_PASSIVE_PROBES` and run by default, despite being active:

| Probe | What it actually does | Why it's active |
|---|---|---|
| `_probe_nacos` | Sends `User-Agent: Nacos-Server` to bypass auth (CVE-2021-29441), reads the user list | Auth-bypass + real data exfil |
| `_probe_clickhouse` | Sends `?query=SELECT 1` | Unauth SQL execution |
| `_probe_druid` | Reads `/druid/websession.json` — live session objects (SESSIONID + Principal) | Live credential-bearing data |
| `_probe_ruoyi` | Reads `/system/user/list` — usernames | PII exfil |

These should be in a gated tier (`_AUTH_BYPASS_PROBES` / `_DATA_READ_PROBES`),
not `_PASSIVE_PROBES`. The ThinkPHP fix was right but incomplete — the
classification of "passive vs active" in `stacks.py` needs a full review.

### Pattern 3 — Exploit-primitive exports with no self-protection (WE25, WE26)
`probes.py` exports live OOB SQLi primitives (Oracle `UTL_HTTP.REQUEST`, MSSQL
`xp_dirtree`, MySQL `LOAD_FILE`) and live command-execution payloads
(`curl {url}`, `sleep {n}`). The docstring says "detection not weaponization",
but the payloads themselves are real exploit-grade strings. There is **no
in-module consent gate** — gating is assumed to live in the caller. If any tool
wires these without checking `MOONMCP_ALLOW_INTRUSIVE`, the agent sends live
SQLi/RCE. The module exports exploit primitives with no self-protective guard.

**The 2026-07-27 `stacks.py` fix is verified present and correct** — but it
only moved ThinkPHP. The residual gap (WE17) is the missing
`MOONMCP_ALLOW_INTRUSIVE` cross-check: `include_rce_probes=True` triggers live
`call_user_func_array` from any context, including a non-intrusive-flagged
session. The opt-in flag is necessary but not sufficient as a lone control.

---

## Module: `waf.py` (126 lines) — WAF/CDN fingerprint

Comprehensive global WAF coverage incl. CN (SafeDog/Yunsuo/Jiasule/BaoTa) and
APAC (WAPPLES/AIWAF/Scutum/Shadan-kun), passive-first, block-page body
signature matching. Strengths.

**WE1 (HIGH):** `active=True` default sends real attack payloads
(`<script>alert(1)`, `OR '1'='1`, `../../../../etc/passwd`) with no
`MOONMCP_ALLOW_INTRUSIVE` gate — only `scope_check`. **WE2 (LOW):** query
param `moon` — fingerprint leak. **WE3 (LOW):** O(n×m) signature scan without
short-circuit.

## Module: `waf_bypass.py` (113 lines) — WAF efficacy testing

Benign canaries, category×transform matrix, baseline diffing. Strengths.

**WE4 (HIGH):** `MOONMCP_ALLOW_INTRUSIVE` gate documented but **NOT enforced**
— `test_waf_efficacy` only takes `scope_check`; the env-var gate doesn't exist
in code. **WE5 (MEDIUM):** `null-byte` transform double-encoded to `%2500` on
the wire — transform silently broken, never tests null-byte bypass. **WE6
(LOW):** `rce` canary `;moonmcp;whoami` contains real `whoami` — intent
fingerprint in blocked-request logs.

## Module: `pathnorm.py` (93 lines) — path-normalization ACL bypass

Purely differential, GET-only, fires only on 401/403 baseline, `verdict:
"review"` defers confirmation. Strengths.

**WE7 (MEDIUM):** `bypass_variants` helper has no scope check — generates
twins for out-of-scope URLs if called directly. **WE8 (LOW):** `severity:
"high"` hardcoded — pre-biases triage.

## Module: `redirect.py` (110 lines) — open redirect

Redirects disabled (canary never contacted), meta-refresh + JS-redirect regex,
backslash-confusion handled, `_with_param` overwrites correctly. Strengths.

**WE9 (MEDIUM):** edge-case `https:/{canary}` single-slash matching — fragile
true positive. **WE10 (LOW):** broad `REDIRECT_PARAMS` (28 incl. `r`/`u`/`to`/
`view`) injects canary into rarely-redirect params → noise. **WE11 (LOW):**
literal `moonmcp-open-redirect.example` canary — tool fingerprint.

## Module: `debugpanel.py` (98 lines) — debug/admin console exposure

Content-signature confirmation avoids soft-404s, severity-tiered panel list,
non-destructive GET-only. Strengths.

**WE12 (LOW):** fixed panel path set — WAF with scanner-path allowlist
trivially detects the probe signature. **WE13 (LOW):** `r.text(limit=12000)`
may truncate past the signature on large panels (actuator/env) → false
negatives.

## Module: `exposure.py` (85 lines) — VCS/config file exposure

Soft-404 rejection via HTML detection, binary signature match (`Bud1`/`DIRC`/
`SQLite format 3`), git remote + recent commits enrichment. Strengths.

**WE14 (MEDIUM):** `/.env` signature is `"="` — far too permissive; any
non-HTML 200 with a stray `=` falsely "confirmed". **WE15 (LOW):** empty-
signature paths (`/.git/logs/HEAD`, `/.svn/entries`, `/.hg/requires`) confirm
on any non-HTML 200 — weaker than rest. **WE16 (LOW):** `recent_commits`
extracts `parts[:2]` (two SHAs) — field name misrepresents content.

## Module: `stacks.py` (304 lines) — CN/RU stack fingerprint + probes

Broad regional coverage, passive fingerprints separated from active probes,
per-probe try/except isolation. The ThinkPHP fix is verified present.

**WE17 (HIGH):** ThinkPHP opt-in has no `MOONMCP_ALLOW_INTRUSIVE` cross-check
— `include_rce_probes=True` triggers live RCE from any context. **WE18
(HIGH):** `_probe_nacos` (auth-bypass + user-list read) misclassified as
passive — runs by default, exfiltrates real user data. **WE19 (HIGH):**
`_probe_clickhouse` (`SELECT 1`) misclassified as passive — runs unauth DB
query by default. **WE20 (MEDIUM):** `_probe_druid` reads live session
objects — passive-tier but exfiltrates session data. **WE21 (MEDIUM):**
`_probe_ruoyi` reads user list (usernames) — passive-tier but exfiltrates PII.
**WE22 (MEDIUM):** `_probe_jeecg` reads report/form lists — enumerated data.
**WE23 (LOW):** generic fingerprint needles (`clickhouse`/`chroma`/`weaviate`)
→ passive FPs. **WE24 (LOW):** `remembeme=deleteme` typo intentional but
undocumented.

## Module: `probes.py` (209 lines) — detection payload definitions

Explicit "detection not weaponization" stance, blind-only CMDi, OAST callbacks
carry no exfil data, timing analyzer rejects uniformly-slow endpoints. Strengths
in intent.

**WE25 (HIGH):** `sqli_oob_payloads` exports live OOB SQLi primitives
(UTL_HTTP/xp_dirtree/LOAD_FILE) with no in-module consent gate. **WE26 (HIGH):**
`cmdi_oob_payloads`/`cmdi_time_payloads` export live command-execution payloads
(curl/sleep) with no in-module consent gate. **WE27 (LOW):** LFI reads
`/etc/passwd` (PII on multi-tenant) — bounded depth but no consent gate. **WE28
(LOW):** `assess_timing` 0.6×requested floor — heavily-loaded server may false-
confirm on long delays.

## Module: `behavior.py` (99 lines) — HTTP behavior profiling

Light benign requests, soft-404 detection with high-entropy random path,
Host-header reflection tested via canary. Strengths.

**WE29 (MEDIUM):** "benign profiling" sends exploit-shaped triggers
(`/%c0%ae%c0%ae/`, `moonmcp[]=1`) with no consent gate — these are known
path-traversal / PHP-array-injection shapes. **WE30 (LOW):** literal
`moonmcp-behaviour-canary.example` canary — tool fingerprint. **WE31 (LOW):**
`Allow`-header split doesn't dedup.

---

## Web bypass/exposure layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| WE4 | waf_bypass | MOONMCP_ALLOW_INTRUSIVE gate documented but NOT enforced | HIGH | S |
| WE17 | stacks | ThinkPHP opt-in has no env-var defense-in-depth cross-check | HIGH | S |
| WE18 | stacks | _probe_nacos (auth-bypass + user-list) misclassified as passive | HIGH | M |
| WE19 | stacks | _probe_clickhouse (SELECT 1) misclassified as passive | HIGH | S |
| WE25 | probes | sqli_oob_payloads exports live OOB SQLi primitives, no consent gate | HIGH | S |
| WE26 | probes | cmdi_oob_payloads exports live cmd-exec payloads, no consent gate | HIGH | S |
| WE1 | waf | active=True default sends real SQLi/XSS/LFI with no intrusive gate | HIGH | S |
| WE20 | stacks | _probe_druid reads live session objects — passive-tier but exfiltrates | MEDIUM | M |
| WE21 | stacks | _probe_ruoyi reads user list — passive-tier but exfiltrates PII | MEDIUM | M |
| WE22 | stacks | _probe_jeecg reads report/form lists — enumerated data | MEDIUM | S |
| WE14 | exposure | /.env signature "=" too permissive — FP on any non-HTML 200 with = | MEDIUM | S |
| WE7 | pathnorm | bypass_variants helper has no scope check | MEDIUM | S |
| WE29 | behavior | "benign profiling" sends exploit-shaped triggers, no consent | MEDIUM | S |
| WE5 | waf_bypass | null-byte transform doubleencoded to %2500 — silently broken | MEDIUM | S |
| WE9 | redirect | edge-case single-slash matching — fragile true positive | MEDIUM | S |
| WE2 | waf | query param "moon" — fingerprint leak | LOW | S |
| WE3 | waf | O(n×m) signature scan without short-circuit | LOW | S |
| WE6 | waf_bypass | rce canary contains real whoami — intent fingerprint | LOW | S |
| WE8 | pathnorm | severity "high" hardcoded — pre-biases triage | LOW | S |
| WE10 | redirect | broad REDIRECT_PARAMS injects canary into rarely-redirect params | LOW | S |
| WE11 | redirect | literal moonmcp-open-redirect canary — tool fingerprint | LOW | S |
| WE12 | debugpanel | fixed panel path set — scanner-path allowlist detects it | LOW | S |
| WE13 | debugpanel | text(12000) may truncate past signature on large panels | LOW | S |
| WE15 | exposure | empty-signature paths confirm on any non-HTML 200 | LOW | S |
| WE16 | exposure | recent_commits extracts two SHAs — field name misleading | LOW | S |
| WE23 | stacks | generic fingerprint needles → passive FPs | LOW | S |
| WE24 | stacks | remembeme=deleteme typo intentional but undocumented | LOW | S |
| WE27 | probes | LFI reads /etc/passwd (PII on multi-tenant) — no consent gate | LOW | S |
| WE28 | probes | assess_timing 0.6×requested floor — loaded server FP | LOW | S |
| WE30 | behavior | literal moonmcp-behaviour-canary — tool fingerprint | LOW | S |
| WE31 | behavior | Allow-header split doesn't dedup | LOW | S |

---

## Recommended next actions (this layer)

1. **WE4 (waf_bypass missing gate)** — smallest HIGH, highest credibility risk.
   Add the `MOONMCP_ALLOW_INTRUSIVE` check that the docstring already promises.
   ~15 min.
2. **WE18 + WE19 + WE20 + WE21 (stacks misclassification)** — reclassify the
   Nacos/ClickHouse/Druid/RuoYi probes into a gated tier. One-line moves +
   a new `_AUTH_BYPASS_PROBES` / `_DATA_READ_PROBES` tuple. ~1 h.
3. **WE25 + WE26 (probes exploit exports)** — add an
   `assert os.environ.get("MOONMCP_ALLOW_INTRUSIVE")` guard in the loader, or
   wrap the export functions in a consent-checking decorator. ~30 min.
4. **WE1 (waf active default)** — flip `active=True` → `active=False` default,
   or gate it. ~15 min.
5. **WE17 (ThinkPHP env cross-check)** — add the `MOONMCP_ALLOW_INTRUSIVE`
   cross-check to `stack_probe`. ~15 min.

The fingerprint leaks (WE2/WE11/WE30 + the `moon*` canaries) are the same
class as the UA leak fixed in the first pass — one sweep to replace every
`moon*`/`Moonmcp*` literal with neutral random strings.

---

## Verification

```bash
python3 -c "from moonmcp.web import waf, waf_bypass, pathnorm, redirect, debugpanel, exposure, stacks, probes, behavior; print('OK')"
python3 -m pytest tests/test_waf.py tests/test_stacks.py tests/test_pathnorm.py tests/test_redirect.py tests/test_exposure.py -q
```