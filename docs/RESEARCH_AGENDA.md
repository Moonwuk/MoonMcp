# MoonMCP Research Agenda

*A prioritized agenda for strengthening MoonMCP, from web research across four
axes: detection coverage, MCP-as-platform, agent ergonomics, and
competitors/ecosystem.*

**Corroboration caveat.** Several primary sources (portswigger.net, arxiv.org,
medium.com, anthropic.com, zaproxy.org) were blocked by the session's egress
policy, so a number of claims below rest on search-index summaries plus
secondary corroboration rather than directly-read primaries — flagged per item
where it matters. Two primary sources *were* read directly:
`github.com/FoxIO-LLC/ja4` and `github.com/PortSwigger/http-request-smuggler`.
Every direction was cross-referenced against MoonMCP's actual current state
(what already ships vs. what is genuinely new).

---

## Top 7 highest-leverage directions

1. **CVE-intelligence layer: EPSS + CISA-KEV + PoC-weighted risk scoring.**
   Today `cve_lookup`/`cve_search` return raw NVD. The emerging de-facto standard
   (cve-mcp-server, 1.1k⭐) converts "Log4j 2.14.1 on :8080" into "CVSS 10 / EPSS
   97% / KEV-confirmed / risk 97" — prioritization the detection layer cannot
   produce itself. Formula: EPSS 35% + KEV 30% + CVSS 20% + PoC 15%, with a hard
   override clamping any KEV-listed CVE to ≥76/CRITICAL. *Clearest single gap.*
   Source: https://github.com/mukul975/cve-mcp-server

2. **Progressive tool discovery — upgrade `tool_catalog` into a `search_tools`
   gateway.** The core problem of a 166-tool server: tool-selection accuracy
   collapses past ~100 tools (BFCL-derived: 43%→2% as tools grew 4→51). Return
   only the 3-5 relevant probe schemas on demand instead of 166 up front.
   Overlaps the internal audit (consolidation + namespacing). Sources: Anthropic
   "Writing effective tools for AI agents" (2025-09-11); "Code execution with
   MCP".

3. **Web cache deception / poisoning probe.** A gap confirmed by both the research
   and the internal audit. Safe A/B signal: authenticated request to a
   static-looking path (`…/nonexistent.css`) → unauthenticated refetch → compare
   bodies + `X-Cache`/`Age`/`CF-Cache-Status`. Major 2024 theme (ChatGPT ATO via
   Wildcard WCD; Kettle "Gotta cache 'em all"). Source:
   https://portswigger.net/research/gotta-cache-em-all

4. **Tool annotations (`readOnlyHint`/`destructiveHint`).** Cheap, honest hints
   that map onto `@active_tool`: mark passive recon read-only, mark
   `sqli_probe`/`cmdi_probe`/`ssrf_*` destructive, so a well-behaved host
   auto-inserts confirmation on the loud tools. Now a common pattern (Burp MCP,
   gokulapap). Not an enforcement mechanism — keep the scope guard. Source: MCP
   spec 2025-06-18 schema; blog 2026-03-16 tool-annotations.

5. **Modernize the desync detector for 2025 variants.** The desync indicator
   predates Kettle's "HTTP/1.1 must die" (Aug 2025): 0.CL, Expect-based oracle,
   TE.0, chunk-extension (CVE-2025-55315, CVSS 9.9). Detect via **root-cause
   parser-discrepancy** (as HTTP Request Smuggler v3.0) rather than fixed
   payloads; only the timeout/non-poisoning signal on a dedicated connection is
   safe. Source: https://github.com/PortSwigger/http-request-smuggler (read
   directly).

6. **Elicitation — a human-authorization gate inside the tool.** A clean way to
   enforce authorization without hardcoded config: mid-scan, ask the operator
   "target X resolves to shared/CDN infra — proceed with active probing?",
   collect scope/identifying-header exactly when needed. The spec forbids using
   elicitation for secrets, but scope confirmation is its ideal case. Source: MCP
   spec 2025-06-18 elicitation.

7. **Exposed source-map harvesting (deepen `recover_sourcemaps`).** Highest
   value-to-risk in the detection-methods sweep; fully passive stdlib. Since
   `recover_sourcemaps` already exists, the work is extending it to a full map of
   hidden endpoints/params that feeds every downstream probe. Source (search
   summary): Sentry "Abusing Exposed Sourcemaps".

---

## By axis (ranked)

### Detection coverage
- **Web cache deception probe** (new) — see Top 7 #3.
- **2025 desync variants** (extend the desync indicator) — see Top 7 #5.
- **Web timing differential oracle** (new; stdlib statistics). Kettle "Listen to
  the whispers" (2024): reliably detect sub-ms differentials → hidden routes,
  SSRF reachability, blind injection. HTTP/2 single-packet precision needs a
  library MoonMCP lacks; fall back to statistical sampling.
- **Cookie-prefix/scope fingerprint** for OAuth cookie-tossing (cheap, passive;
  extend the ATO detectors). Flag missing `__Host-`/`__Secure-` prefixes and
  `Domain`-scoped session cookies. Source: Snyk Labs (2024-11-26).
- **Error-based blind SSTI** ("Successful Errors", 2025) — extend
  `ssti_probe`/`interp_probe` to fingerprint the engine from distinctive error
  responses even with no reflected output.
- **WorstFit / Windows Best-Fit encoding-differential corpus** — new payload set
  for LFI/argument-injection on Windows/PHP-CGI stacks. Source: DEVCORE / Orange
  Tsai (2025-01-09).
- **Static Path Deception / Cache Key Confusion** — extend `parser_diff_probe`.
- CSWSH-over-GraphQL is **already tracked** as `cswsh_probe` (§3.5 of
  RESEARCH_GAPS.md).

### MCP platform
- **Tool annotations** — see Top 7 #4.
- **Elicitation** — see Top 7 #6.
- **Sampling** (server-initiated LLM): have a tool ask the host model to classify
  "diff = bug or noise", synthesize a context-aware payload, or rank a large
  sweep. Powerful but adds model-in-loop complexity; permissions/cost stay
  client-side.
- **Output schemas / structured content**: return typed findings instead of
  loose dicts → reliable cross-tool chaining and cleaner dedup.
- **Progress notifications**: live status on long sweeps instead of a silent
  multi-minute hang.
- **Resource templates**: `cve://{product}/{version}`, `finding://{id}`,
  `wordlist://{category}` (MoonMCP already exposes 11 resources incl.
  `findings://`).
- *Later:* Streamable HTTP + OAuth 2.1 Resource Server → multi-operator team
  deployment with per-analyst scoped tokens.
- *Watch:* the 2026-07-28 RC deprecates roots/sampling/logging — build against
  the 2025-11-25 stable baseline, treat RC items as forward-looking.

### Agent ergonomics (highest ROI at 166 tools)
- **Progressive tool discovery** — see Top 7 #2.
- **Consolidate tool families** behind a `mode=` param (overlaps the audit).
- **Namespacing** (`recon_*`/`inject_*`/`db_*`/…) as a coarse routing signal.
- **Result shaping**: `response_format=concise|detailed` (~⅔ token saving),
  semantic fields over raw IDs, ~25k-token cap, meaningful empty results.
- **Structured errors for the model**: `{error:"scope_violation", action:"…"}` —
  teach the model to self-correct instead of aborting (fits the `@active_tool`
  scope denials).
- **Agentic eval harness**: extend the existing probe precision/recall metrics
  from "does the probe detect the bug?" to "does the agent pick the right probe,
  pass valid args, and stay in budget?"
- Sources: Anthropic "Writing effective tools for AI agents" (2025-09-11),
  "Building effective agents" (2024-12-19), "Effective harnesses for long-running
  agents".

### Competitors & ecosystem
- **CVE-intelligence enrichment** — see Top 7 #1.
- **Decision / parameter-optimization + failure-recovery layer** (HexStrike
  pattern): auto-tune flags and fall back on rate-limits instead of stalling the
  loop.
- **LRU result caching** for repeated recon.
- **DNSTwist typosquat / Semgrep SAST** as first-class surfaces (FuzzingLabs).
- **Per-call audit logging** — a standard in mature security MCP servers.
- Strategic read: detection MCPs win on breadth/speed/scope-safety; autonomous
  agents win on validated PoCs. The durable pattern is pairing them (cheap recon
  → expensive confirmation) — MoonMCP's existing Strix-orchestration approach.

---

## Convergence with the internal audit

CSP analysis, cache-deception, tool consolidation/search, and tool annotations
surfaced **independently in both** the internal code audit (see
[`PROJECT_AUDIT.md`](PROJECT_AUDIT.md)) and this external research. Where the
code review and the market survey point at the same place, the signal is
strongest — **cache-deception, consolidation/tool-search, and tool annotations**
are the best-supported candidates.

---

## Not yet completed

The web-research pass's synthesis and adversarial fact-check stages, plus the
"tooling-ecosystem" and local-state agents, did not finish (session limit). The
material above is recovered from the completed research agents and
cross-referenced by hand; it has **not** been through a second automated
fact-check pass. Treat search-summary-level claims accordingly.
