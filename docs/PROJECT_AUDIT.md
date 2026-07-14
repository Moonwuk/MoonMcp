# MoonMCP Project Audit

*Internal code audit — redundancy, dead code, consolidation, drift, bloat, and coverage gaps.*

**Method.** Six independent audit lenses (functional duplication, dead code,
consolidation, missing coverage, catalog/doc drift, bloat) fanned out over the
codebase; every raw finding was then adversarially verified against the actual
source before inclusion. 21 findings survived verification (0 refuted), but many
were **downgraded** to "partial" with corrected claims — the recurring reason
being that MoonMCP deliberately values *catalog discoverability* (each capability
listed by name so an agent can find it) and its shared mechanics are often
*already* factored into `web/` modules. So most "consolidate" items are optional
judgment calls, not defects.

---

## Top recommendations (highest signal)

1. **Add CSP policy-strength analysis** — the one *confirmed* real coverage gap.
   CSP is currently graded present-vs-absent only, so a worthless-but-present CSP
   (`unsafe-inline`/`unsafe-eval`, wildcard/`data:` sources, missing
   `object-src`/`base-uri`) is silently scored as protected. Concrete, low-risk,
   passive. *(Confidence: High — confirmed.)*

2. **Fix the stale tool-count drift across three files** — README says both 166
   and 158; SKILL.md says ~158; `catalog.py` docstring says "120+ tools / 90
   docstrings." Real count is **166** (verified live). *(Confidence: High —
   confirmed.)*

3. **De-duplicate the OAST-collection epilogue** — a ~10-line "collect OAST
   interactions" block is copy-pasted across ~7-8 probe bodies in `server.py`.
   One shared helper removes ~90 lines and eliminates drift risk. *(Confidence:
   High — partial; count corrected to ~7-8.)*

4. **Fix the dead `db_credential_scan` docstring reference** in
   `recon/deserialize.py:13` — it names a tool that does not exist. The correct
   replacement is `analyze_config` (or drop the name), **NOT** `db_exposure`.
   *(Confidence: High — partial.)*

5. **(Optional) Fold the four `*_search` KB tools into their `*_info` siblings** —
   mechanically exact, removes 4 tools, consistent with the existing
   `privesc_tools` pattern. Clean consolidation *if* you prioritize a lean
   catalog; leave as-is if you prioritize per-mode discoverability. *(Confidence:
   High — partial; a genuine trade-off, not a defect.)*

---

## 1. Duplicates / overlap to resolve

**1.1 — OAST-collection epilogue copy-pasted across ~7-8 probe bodies** *(Medium)*
A near-identical ~10-line epilogue (self-hosted `ctx.oast_server.interactions()`
else `ctx.oast.poll_target()` → `http.fetch` → `oastmod.parse_interactions()`
with `except: []`) is duplicated across ~7 probe bodies plus one token-keyed
variant. `ssrf_protocol_probe` already extracted this into a local `_poll(cb)`
helper, proving it is trivially factorable. **Action:** add one
`async def collect_oast(ctx, token) -> list` helper; replace the copies. **Leave
`oast_poll` alone** — it is a separate diagnostic tool with intentionally
different semantics.

**1.2 — WAF/CDN signatures overlap across three files** *(Low — reasonable to
leave as-is)* The marquee WAF/CDN indicators for ~4-6 big vendors are duplicated
across `web/waf.py`, `knowledge/waf_kb.py`/`waf_kb_data.py`, and
`recon/fingerprint.py`. But these hold different, largely non-overlapping vendor
sets in three deliberately different formats (structured tuples for live
matching; versioned regexes; human-readable prose). **Do NOT** source all three
from `waf_kb_data` — its prose cannot drive field-scoped/versioned matching and
would *regress* detection. At most a low-priority DRY between `web/waf.py` and
`fingerprint.py` only.

---

## 2. Consolidation candidates (mostly judgment calls)

**2.1 — Four `*_search` KB tools fold into their `*_info` siblings** *(Medium)*
`injection_search`/`technique_search`/`privesc_search`/`vuln_search` are one-line
wrappers; a `search=` param on the `*_info` tools absorbs all four (−4 tools).
The codebase is already inconsistent — `privesc_tools` merges search while the
four main KBs keep it split. Trade-off: lean catalog vs. per-mode
discoverability. **Do NOT merge across KB domains.**

**2.2 — `logic_probe` / `value_probe` overlap on money-param tampering** *(Low)*
They share a numeric-tamper core (already factored through `web/logic.py`) but
each owns a distinct capability (logic = mass-assignment; value = currency-swap,
coupon reuse, precision/>100%-discount). **Keep both.** To remove the one real
overlap, narrow `logic_probe`'s `NUMERIC_PARAM_RE` so money fields are tampered
by exactly one tool.

**2.3 — `access_control_check` / `authz_probe` share a cross-identity-diff core**
*(Low)* Both replay a URL under two identities and flag near-identical bodies via
`SequenceMatcher >= 0.95`; that ~5-line check is duplicated. But neither
subsumes the other (access_control_check is arbitrary-method incl. POST + custom
body; authz_probe is GET-only, findings-only). **Keep both; factor only the
similarity helper.**

**2.4 — `nosqli_probe` / `graphql_nosqli`** *(Leave as-is)* Both do Mongo
operator injection and already share `has_session_cookie` + the nosqli
error-signature KB, but payload sets, Resp models, and assessors diverge. The
residual duplication is the abstract idea, not code.

**2.5 — Three intrusive SSRF probes** *(Leave separate)* `ssrf_probe`,
`ssrf_metadata_probe`, `ssrf_protocol_probe` have different signatures, modules,
and detection channels (response-based vs OOB vs port-reachability). A `mode=`
merge would fold together distinct preconditions and return shapes.

**2.6 — `jwt_analyze` / `jwt_crack` / `jwt_alg_confusion` offline trio** *(Leave
as-is)* All three are offline `@safe_tool` tools, but each carries a different
required input; a `jwt(mode=...)` merge would produce awkward mode-conditional
required params. Worth a documentation/grouping note only.

**2.7 — `desync_probe` / `desync_modern_probe`** *(Keep separate)* Different
techniques (framing-ambiguity vs timeout-differential), different result
dataclasses. Modern desync is a named 2025 class. At most a thin
`mode='classic'|'modern'|'all'` wrapper; do not collapse the result types.

**2.8 — `cve_lookup` / `cve_search`** *(Leave as-is)* Different NVD endpoints
(`?cveId=` vs `?keywordSearch=`) and return types. Lookup-by-ID vs
search-by-keyword is a standard self-documenting split.

---

## 3. Dead code / orphans to remove

**This category came back essentially empty — a good sign about the codebase.**
No orphaned/unregistered tools or dead code paths survived verification. KB data
files were specifically checked for duplicate/orphan entries and came back clean
(see 5.3). The one adjacent item is a dead docstring reference (4.3).

---

## 4. Drift / consistency fixes

**4.1 — README self-contradicts on tool count: 166 vs 158** *(High, confirmed)*
Headline (L54) says 166; architecture-tree comment (L475) says 158. Live
registration = **166**. **Action:** change `README.md:475` to "166 tools".

**4.2 — SKILL.md advertises ~158 tools** *(Medium, confirmed)*
`.claude/skills/moonmcp/SKILL.md:16` says "~158 tools"; real count is 166.
**Action:** update, or better — drop the hard number since the "~" already
drifted.

**4.3 — Docstring references a non-existent tool `db_credential_scan`** *(Medium,
partial)* `moonmcp/recon/deserialize.py:13` cites `db_credential_scan` as a
"classify, don't exploit" sibling. No such tool is registered — it shipped as
`extract_secrets` **and** `analyze_config`. **Action:** drop the name or replace
with `analyze_config`. **Do NOT substitute `db_exposure`** (it is a separate,
intrusive datastore sweep — the opposite of the passive boundary described).

**4.4 — catalog.py docstring says "120+ tools / read 90 docstrings"** *(Low,
confirmed)* The same file's FAMILIES enumerates 166. **Action:** prefer
count-agnostic prose ("a large tool surface"), durable as the surface grows.

---

## 5. Bloat to trim

**5.1 — server.py is a 6017-line monolith holding all 166 tool definitions**
*(Low)* All 166 `@mcp.tool` defs in one file, ~11.7× the next code module.
Optional cleanup: split registrations into `server/<family>.py` modules keyed off
the 11 FAMILIES, leaving `server.py` a thin assembler. Weigh against the
single-registration-surface design. **Not required.**

**5.2 — `sqli_probe` body is ~150 lines (largest tool)** *(Optional)* Largest
because it carries four opt-in lanes (multibyte/waf_bypass/time_based/oob) plus
core detection; it already delegates payloads/assessment to `web/probes.py`.
There is **no** sqli-specific architectural drift (nosqli/second-order probes
also orchestrate inline). Treat as optional size polish only, not a consistency
fix.

**5.3 — Large KB data files are justified, NOT bloat (leave as-is)** Legitimate
curated offline KBs (`privesc_data` = 129 techniques + 68 tools; `techniques` =
115; `vulns` = 44 + 13 root-causes + 29 tools; `injections` = 29) with **zero
duplicate ids**; each paired with a thin query API. The lone reused id
(`insecure-deserialization` across SERVER_SIDE_VULNS and ROOT_CAUSES) is an
intentional foreign key. The small-representative-set discipline applies to probe
payload tables, not these reference catalogs.

---

## 6. Genuine missing coverage

**6.1 — No CSP policy-strength / bypassability analysis** *(Medium, **confirmed**
— the only fully-confirmed gap)* `audit_headers` scores CSP purely
present-vs-absent; a present-but-worthless CSP is graded as fully protected. No
directive parsing exists. (`cspp_probe` in the catalog is *client-side prototype
pollution*, unrelated.) **Action:** add passive CSP directive parsing that
downgrades a CSP containing `unsafe-inline`/`unsafe-eval`, wildcard `*` or
`data:`/`blob:` sources in `script-src`/`default-src`, or missing
`object-src`/`base-uri`. Detection-only, no extra requests. **Best-value new
capability in this report.**

**6.2 — No native XSS probe** *(By-design, not a gap)* Reflected-param XSS is
explicitly delegated to nuclei `-dast`/dalfox; DOM-XSS **sink** detection already
ships via `cspp_probe`/`jslibs`; the `xss` lead kind routes to `confirm_finding`.
A native reflected-XSS probe would contradict the project's encoded delegate
strategy. The only defensible native edge is a **DOM-XSS taint probe**
(browser-observed), as an optional enhancement.

**6.3 — LDAP and XPath injection are KB-only (no probe)** *(Medium)* `ldapi` and
`xpath` are full KB entries with no probe — but they are not uniquely abandoned:
of 29 catalogued injection classes, ~13 are KB-only by design. If pursuing
probe-parity, add small differential detectors mirroring `nosqli_probe`, but
frame as one item within a ~13-class effort.

**6.4 — No generic anti-CSRF-token detector for state-changing HTTP endpoints**
*(Low — defer)* CSRF is inferred passively from a missing SameSite cookie; active
cross-origin-rejection detection already exists for WebSockets (CSWSH) and
GraphQL GET-CSRF, plus CORS/OAuth `state`. The narrow remaining gap
(token-presence on generic HTTP endpoints) is hard to test safely without an
authenticated session and overlaps existing signals.

---

## Summary: what to action vs leave alone

- **Do now (confirmed, cheap, high-value):** CSP analysis (6.1); the three
  doc-count fixes (4.1, 4.2, 4.4); the `db_credential_scan` docstring fix to
  `analyze_config`/drop (4.3).
- **Good cleanups (real, low-risk):** OAST epilogue helper (1.1); optionally fold
  the four `*_search` tools (2.1); narrow `logic_probe`'s money regex (2.2);
  factor the authz similarity helper (2.3).
- **Optional / judgment calls:** server.py split (5.1); sqli_probe size polish
  (5.2); DOM-XSS taint probe (6.2); LDAP/XPath as part of a broader probe-parity
  effort (6.3).
- **Honestly leave as-is:** WAF consolidation (1.2 — would regress);
  nosqli/graphqli (2.4); three SSRF probes (2.5); JWT trio (2.6); desync pair
  (2.7); cve pair (2.8); KB data files (5.3); generic CSRF probe (6.4).
- **Empty category (good sign):** Dead code / orphans — none found.
