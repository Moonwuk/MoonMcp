---
name: idea-gen
description: >-
  Generate ideas for MoonMCP work in two distinct modes. Mode A: brainstorm a
  ranked, non-redundant list of attack-vector hypotheses for a specific in-scope
  target, grounded in this engagement's actual recon signal rather than a generic
  checklist. Mode B: propose new MoonMCP tools/capabilities by sourcing from
  recent security research, Burp/ZAP marketplaces, and competitor MCP servers,
  then cross-referencing against docs/RESEARCH_GAPS.md, docs/ROADMAP.md, and
  moonmcp/catalog.py so nothing already covered gets re-proposed. Triggers:
  "what should I try next on", "brainstorm attack vectors for", "propose new
  capabilities for MoonMCP", "what's missing", "research X for gaps", "find new
  tool ideas".
---

# Idea generation skill

Two independent modes live here. Mode A brainstorms **what to try next against a
target already in this engagement**. Mode B brainstorms **what MoonMCP itself
should grow next**. Pick the mode by what's being asked about — a target/host
name means Mode A, a capability/gap/research question means Mode B. Don't mix
them: Mode A never proposes new tools, Mode B never touches a live target.

## Mode A — Attack-vector brainstorming for a scoped target

Triggered by "what should I try next on `<target>`" / "brainstorm attack vectors
for `<target>`". Output a ranked, non-redundant set of testable hypotheses
grounded in this engagement's actual recon signal — never a generic checklist.

**RECALL.** Pull everything already known before touching the target again:
- `memory_brief(target)` — one-shot rollup of entities, findings, leads, cross-target lessons.
- `memory_search(query=target, target=target)` (add `trust="curated"` to skip unverified scraped noise) for anything `memory_brief` truncated.
- `memory_lesson(action="recall", query=target or the tech name)` — prior tradecraft that might rule an approach in or out (e.g. a WAF that already eats a payload class here).
- `list_findings(target)` — confirmed/labelled findings and their `outcome` (true_positive/false_positive/duplicate/wont_fix).

**SIGNAL.** Pull the entity graph rather than re-scanning: `memory_graph(target)`
returns `technology`, `service`, `endpoint`, `param`, `credential`, `cve`, and
`asset` nodes already discovered. Only when a needed signal is genuinely missing
(no tech fingerprint, no endpoint list) recommend the one specific light-active
tool that produces it — `fingerprint`, `analyze_headers`, `tls_inspect`,
`well_known`, `crawl`, `waf_detect`, `parse_openapi`,
`discover_parameters` — before hypothesizing further. Don't guess where a
one-tool-call answer exists. (`identify_waf` is a separate, offline knowledge-base
lookup — it matches text you already captured against vendor fingerprints and
sends no traffic itself; reach for it in CROSS-REF alongside `waf_info`, not here.)

**CROSS-REF.** For each distinct technology/service/endpoint/param entity, query
the offline catalogs to find matching vuln classes:
- `technique_info(technology_or_cve)` / `technique_info(query=…)` for framework/language-specific techniques and known CVEs.
- `vuln_info(...)` / `vuln_info(query=…)`, and `rootcause_info(root_cause)` to trace a signal (e.g. "deserialization", "SSRF") back to its derived vuln classes.
- `injection_info(class)` / `injection_info(query=…)` for any parameter or input surface.
- `privesc_info` (with `query=`) if auth/role boundaries were observed.
- `waf_info` if a WAF was fingerprinted, to know what it likely blocks — or
  `identify_waf` to name the vendor from a raw captured response/blocking page
  (both offline, no traffic).
- `cve_lookup(cve_id)` / `cve_search(keyword)` for version-specific live matches against fingerprinted products.

**RANK.** Score each candidate on **Impact** (severity from the catalog entry) ×
**Presence-likelihood** (how directly a *real* recon signal — not a guess —
implies this class applies to this stack) × **Ease-of-test** (favor a single
light/passive tool call over an intrusive, gated, multi-step chain). Sort
descending. Before finalizing, drop or demote anything that:
- matches a finding already `true_positive`/`duplicate` in `list_findings`,
- matches an open, unconfirmed lead already in memory (`kind=lead`) — surface it as "pending verification" via `promote_lead`/`confirm_finding` instead of listing it as a fresh hypothesis,
- is contradicted by a recalled `memory_lesson` (e.g. "this stack's WAF normalizes CRLF, skip that class here").

**OUTPUT.** 5–8 ranked entries, each: **Hypothesis** — *Signal* (recon fact +
its source) — *Cross-ref* (catalog entry consulted) — *Test* (exact MoonMCP
tool/sequence) — *Rank note* (impact × presence × effort).

### Worked example — target `shop.example.co`

Recon on file (via `memory_graph`): Node/Express + GraphQL at `/graphql`, JWT
cookie auth, AWS-hosted (per `host_intel`), React frontend with `.map` files seen
during `crawl`, Cloudflare WAF identified. Existing findings: one confirmed
low-severity reflected XSS (`true_positive` — excluded below); one open lead,
"possible open redirect on `/login?next=`" — not re-listed, flagged for
`confirm_finding` instead.

1. **GraphQL authorization bypass** — Signal: `/graphql` endpoint from `memory_graph`. Cross-ref: `vuln_info(query="graphql")`, `injection_info(query="graphql")`. Test: `graphql_check` → `graphql_probe` → `authz_probe`. High×High×Medium.
2. **JWT alg-confusion / weak signing** — Signal: JWT cookie seen during fingerprinting. Cross-ref: `technique_info("jwt")`. Test: `jwt_analyze` → `jwt_alg_confusion` → `jwt_crack`. High×High×Low.
3. **SSRF via cloud metadata** — Signal: AWS hosting confirmed by `host_intel`. Cross-ref: `rootcause_info("ssrf")`, `vuln_info`. Test: `ssrf_metadata_probe` (intrusive, needs consent). High×Medium×Medium.
4. **Sourcemap-leaked API surface** — Signal: `.map` files seen in `crawl`. Cross-ref: `technique_info(query="sourcemap")`. Test: `analyze_js` (detects the map) → `recover_sourcemaps` (reconstructs it) → `discover_parameters`. Medium×High×Low.
5. **Cloud storage misconfiguration** — Signal: AWS infra + brand name. Cross-ref: `vuln_info(query="s3")`. Test: `cloud_buckets`. Medium×Medium×Low.
6. **JS-library CVE match** — Signal: front-end libraries fingerprinted via `crawl`. Cross-ref: `cve_search(library_name)`. Test: `js_library_scan` → `cve_lookup(cve_id)`. Medium×Medium×Low.

Any hypothesis confirmed goes to `add_finding`; anything disproven gets
`label_finding(outcome="false_positive")` and, if reusable, a `memory_lesson` —
full guidance on both: the `memory` skill.

## Mode B — Propose new MoonMCP capabilities

Triggered by "propose new capabilities for MoonMCP," "what's missing," "research
X for gaps," or "find new tool ideas." Run the process end to end — never skip
the cross-reference step, since a duplicate proposal is worse than no proposal.

**DOCS.** Open `docs/RESEARCH_GAPS.md` and `docs/ROADMAP.md` in full before
anything else. RESEARCH_GAPS.md is the authoritative gap ledger — check its
Status legend (❌ not covered / 🟡 partial / ✅ covered) so nothing already
tracked or shipped gets re-proposed, and read its priority-build-order table and
tooling-strategy section, which encode this project's ranking logic. ROADMAP.md
shows the current phase and which `⏭️` items are already queued — an idea that
duplicates a queued `⏭️` item gets merged into it, not re-proposed.

**SOURCE.** Source candidates from four lanes, matching whatever the user pointed
at (a CVE, a research theme, or "just find gaps"):
1. Recent security research — CVEs, conference talks (DEF CON/Black Hat/OWASP), vendor advisories, and, per RESEARCH_GAPS.md's own method, national/regional security communities in their own languages (Chinese, Russian, Japanese, Korean, Vietnamese, Turkish, Persian, EU, LATAM, India/MENA/SEA), not only English-language sources. Use the `web-research` skill's tools for this legwork rather than reimplementing search/read/dork logic here.
2. Burp Suite's BApp Store and ZAP's add-on marketplace — scan plugin descriptions for detection techniques not yet in MoonMCP.
3. This project's own docs — re-scan RESEARCH_GAPS.md themes for ❌ entries that fit the ask.
4. Competitor MCP security servers — what capabilities do other bug-bounty/pentest MCP projects expose, as a sanity check on category coverage.

Every candidate must be backed by a CVE, a public PoC, or a primary write-up —
reject speculative gaps with no such backing, exactly as RESEARCH_GAPS.md
requires.

**CROSS-REF.** Read `moonmcp/catalog.py`'s `FAMILIES` OrderedDict directly rather
than relying on memory — check every surviving candidate against all 11 named
families: `setup`, `passive_osint`, `light_active`, `intrusive`,
`orchestration`, `infra`, `intercept`, `knowledge`, `reporting`, `memory`,
`external`. Grep the catalog for keyword overlaps (e.g. a "GraphQL injection"
idea must be checked against `graphql_check`/`graphql_probe`/`graphql_nosqli`; a
"deserialization" idea against
`deserialize_fingerprint`/`fastjson_oast_probe`). If an idea is already covered,
drop it or reframe it as an enhancement to the existing tool instead of a new
one.

**RANK.** Rank whatever survives against this project's discipline:
- Detection-only, always — fingerprint/confirm a condition, never exploit it. Anything requiring real exploitation or weaponization gets deferred to sqlmap or Strix, not built natively (see the `strix-orchestration` skill for that hand-off).
- Prefer active differential probes (send a request, diff a response, time a response) over "more reference text" — `knowledge` is already large; new KB entries rank below new active probes.
- Prefer small, representative payload/lane sets over exhaustive enumeration, matching the existing intrusive-family probes' style.
- Prefer ideas that reuse existing plumbing (an existing HTTP client, OAST callback infra, JWT/crawl utilities) over ideas requiring new infrastructure.
- Apply the nuclei-delegation test: if nuclei can already express the check as a template, delegate to `vuln_scan` (MoonMCP's nuclei wrapper) instead of building native; only build native when the check needs stateful, differential, timing-based, or business-logic handling nuclei structurally can't do.
- Match the naming/style of the family it would join (e.g. an `_probe` suffix for active differential detectors in `intercept`/`light_active`/`intrusive`).

**OUTPUT.** Output as a numbered, ranked list, same shape as the shipped 8-item set
(`cmdi_probe`, `jwt_alg_confusion`, `lfi_probe`, `deserialize_fingerprint`,
`xxe_probe`, `js_library_scan`, `interp_probe`, `saml_xsw_probe`). Each entry:
proposed tool name, one-line rationale citing the CVE/PoC/source, and the exact
`catalog.py` family it would slot into.

### Worked example (an actual open ❌ entry in RESEARCH_GAPS.md, §3.5)

> **`cswsh_probe`** — Cross-Site WebSocket Hijacking: WS handshakes authed
> only by cookie, with no `Origin` validation (CWE-1385), let a foreign origin
> complete the upgrade and hijack the session. Mapping: send `Upgrade:
> websocket` twice — once with the legitimate `Origin` + session cookie, once
> with a foreign `Origin` + the same cookie; a `101 Switching Protocols`
> response to the foreign Origin is the CSWSH signal. Never sends frames
> (detection only). Slots into `light_active`, alongside `ws_probe`, reusing its
> WebSocket handshake plumbing.

If asked to persist the result, append new entries to RESEARCH_GAPS.md using its
exact skeleton (`### <n>. <name> ❌`, technique sentence(s), `- Source:`,
`- **Mapping:**`) and update ROADMAP.md's phase list — never silently mark
anything ✅.

## Relationship to other skills

This skill only decides *what to try* or *what to build next* — it calls out to
the tools that actually do the work rather than reimplementing them. Recall and
persistence (`memory_brief`, `memory_search`, `memory_lesson`, `add_finding`,
`label_finding`) are the `memory` skill's territory. External research legwork
(searching, dorking, reading pages) in Mode B's SOURCE lane is the
`web-research` skill's territory. Turning a Mode A hypothesis into a validated
proof-of-concept, or deciding a candidate needs Strix instead of a native
MoonMCP tool in Mode B, is the `strix-orchestration` skill's territory. Broader
recon/testing mechanics for a target belong to the `moonmcp` skill. This skill
never duplicates their logic — it only decides ranking and sourcing, then hands
off.
