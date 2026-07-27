# MoonMCP — Research: The Bug-Bounty MCP Server Landscape

> This document records the research that grounded MoonMCP's design. A fan-out
> research harness discovered **161 candidate projects**, deep-read **24**, and
> confirmed **23** as real bug-bounty / offensive-security MCP servers. The
> design synthesis below is the blueprint the implementation follows.

## Servers surveyed

| Server | Lang | Tools | Approach — wraps |
| --- | --- | --- | --- |
| [0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents) | Shell/Markdown | 50 | nmap, masscan, rustscan, subfinder, amass, httpx |
| [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) | Python | 40 | nmap, rustscan, masscan, autorecon, amass, subfinder |
| [BurpMCP-Ultra](https://github.com/Cy-S3c/BurpMCP-Ultra) | Kotlin | 40 | Burp Suite Professional, Burp Collaborator, PortSwigger BCheck DSL, OpenAPI/Swag |
| [akinabudu/bug-bounty-mcp](https://github.com/akinabudu/bug-bounty-mcp) | Python | 37 | subfinder, amass, gospider, katana, masscan, nmap |
| [cyproxio/mcp-for-security](https://github.com/cyproxio/mcp-for-security) | TypeScript | 32 | — (native / API / KB) |
| [VulneraMCP](https://github.com/telmon95/VulneraMCP) | TypeScript 5.5 | 23 | OWASP ZAP, Caido, Subfinder, Amass, HTTPx, sqlmap |
| [SlanyCukr/bugbounty-mcp-server](https://github.com/SlanyCukr/bugbounty-mcp-server) | Python | 21 | nmap, nmap_advanced, rustscan, masscan, amass, subfinder |
| [appsecco/vulnerable-mcp-servers-lab](https://github.com/appsecco/vulnerable-mcp-servers-lab) | JavaScript | 21 | — (native / API / KB) |
| [gokulapap/bugbounty-mcp-server](https://github.com/gokulapap/bugbounty-mcp-server) | Python 3.10+ | 19 | whois, Shodan, Censys, Hunter.io API, crt.sh, archive.org CDX API |
| [pentest-mcp (DMontgomery40/pentest-mcp)](https://github.com/dmontgomery40/pentest-mcp) | TypeScript | 19 | nmap, john, hashcat, gobuster, nikto, subfinder |
| [PentestAgent (GHOSTCREW) — 0xSojalSec fork](https://github.com/0xSojalSec/PentestAgent) | Python | 18 | nmap, metasploit, ffuf, sqlmap, nuclei, hydra |
| [R-s0n/rs0n-bug-bounty-mcp-server](https://github.com/R-s0n/rs0n-bug-bounty-mcp-server) | JavaScript/Typ | 14 | — (native / API / KB) |
| [hackerone-mcp](https://github.com/c0tton-fluff/hackerone-mcp) | Go | 14 | — (native / API / KB) |
| [pentest-ai (ptai)](https://github.com/0xsteph/pentest-ai) | Python | 14 | nmap, masscan, nuclei, ffuf, sqlmap, gobuster |
| [h1-brain (PatrikFehrenbach/h1-brain)](https://github.com/PatrikFehrenbach/h1-brain) | Python 3.10+ | 12 | HackerOne REST API |
| [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) | Python | 11 | nmap, masscan, shodan, zoomeye, networksdb, whatweb |
| [swgee/BurpMCP](https://github.com/swgee/BurpMCP) | Java | 10 | Burp Suite, Burp Collaborator |
| [six2dez/burp-ai-agent (Custom AI Agent for Burp Suite)](https://github.com/six2dez/burp-ai-agent) | Kotlin | 10 | — (native / API / KB) |
| [ExternalAttacker-MCP](https://github.com/MorDavid/ExternalAttacker-MCP) | Python | 8 | subfinder, naabu, httpx, nuclei, cdncheck, tlsx |
| [pd-tools-mcp (ProjectDiscovery MCP Server)](https://github.com/intelligent-ears/pd-tools-mcp) | TypeScript | 7 | subfinder, dnsx, naabu, httpx, katana, nuclei |
| [Pentest-MCP (Vasanthadithya-mundrathi)](https://github.com/Vasanthadithya-mundrathi/Pentest-MCP) | Python 3 | 7 | nmap, masscan, nikto, sqlmap, gobuster, hydra |
| [Cyreslab-AI/burpsuite-mcp-server](https://github.com/Cyreslab-AI/burpsuite-mcp-server) | TypeScript/Jav | 5 | Burp Suite Professional |
| [PentestThinkingMCP](https://github.com/ibrahimsaleem/PentestThinkingMCP) | JavaScript/Nod | 1 | — (native / API / KB) |
| [awesome-bugbounty-mcp (BehiSecc)](https://github.com/BehiSecc/awesome-bugbounty-mcp) | Markdown | 0 | mcp-recon, Shodan MCP, Censys MCP, Firecrawl MCP, Screenshot Website MCP, Fetch  |

---

# Design Synthesis: A Best-of-Breed Bug-Bounty MCP Server

*Blueprint derived from analysis of 23 existing offensive-security MCP servers.*

---

## 1. Landscape Summary

### Group A — CLI-wrapper servers (shell out to real binaries)
These delegate all real work to installed security binaries (subfinder, nuclei, nmap, sqlmap…). The MCP layer is orchestration + output plumbing.

| Server | Stars | 1-line takeaway |
|---|---|---|
| **HexStrike AI** (0x4m4) | ~10.2k | Widest arsenal (150+ tools) *and* exposes raw RCE primitives (arbitrary command/file/pip) — powerful, reckless, no auth. |
| **cyproxio/mcp-for-security** | ~620 | Clean 24-server monorepo template; but every tool takes free-form `*_args` = argument injection by design. Now archived. |
| **FuzzingLabs/mcp-security-hub** | ~712 | 38 Dockerized servers, non-root, capability-dropping — best *packaging* hygiene, but no scope enforcement in code. |
| **SlanyCukr/bugbounty-mcp-server** | ~2 | Nice two-tier FastMCP-proxy → Flask-backend split; string-concat command building = injection risk. |
| **ExternalAttacker-MCP** (MorDavid) | ~76 | ProjectDiscovery toolchain via `Popen(shell=False)` (good), but auth + input validation are commented out; auto-updates run remote code (RCE). |
| **pd-tools-mcp** (intelligent-ears) | ~4 | Minimal, correct `spawn()` argv usage, chained recon workflow; no scope, no timeouts. |
| **akinabudu/bug-bounty-mcp** | ~5 | Only one with a real **program/scope model** + `validate_target` gate + result auto-filtering — the idea to steal. |
| **Vasanthadithya/Pentest-MCP** | ~6 | Kali container + `run_command_sync`/`start_job` = arbitrary `shell=True` execution. Anti-pattern showcase. |

### Group B — API-wrapper / knowledge servers (no scanning, no shell-out)
Safe by construction; they read data or serve knowledge.

| Server | Stars | 1-line takeaway |
|---|---|---|
| **h1-brain** (PatrikFehrenbach) | ~324 | Read-only HackerOne API + local SQLite of 3,600+ disclosed reports; `hack()` orchestrator builds an "attack briefing." Great recon-intel pattern. |
| **hackerone-mcp** (c0tton-fluff) | ~2 | Go H1 API client with read *and* write/triage tools — clean read/write split, but LLM can mutate live reports (prompt-injection risk). |
| **R-s0n rs0n-bug-bounty** | ~16 | Pure local knowledge base (PayloadsAllTheThings/HackTricks/SecLists + 778 reports). No network at runtime. |
| **PentestThinkingMCP** | ~36 | In-memory beam-search "reasoning" tool; markets MCTS it doesn't implement. Planning aid only. |

### Group C — Hybrid (shell-out + native heuristics + browser + APIs)
| Server | Stars | 1-line takeaway |
|---|---|---|
| **pentest-ai / ptai** (0xsteph) | ~1.3k | Best safety design: host-locked scope guard, N-of-N "oracle" verification, proof capsules, spend caps, OAST. The bar to beat. |
| **VulneraMCP** (telmon95) | ~34 | CLIs + ZAP/Caido APIs + Puppeteer + Postgres persistence + dashboard; native XSS/SQLi heuristics are shallow. |
| **gokulapap/bugbounty-mcp-server** | ~36 | Advertises 92 tools; many are placeholders returning query strings; vuln tests are home-grown aiohttp regex matching. README overstatement cautionary tale. |
| **dmontgomery40/pentest-mcp** | ~138 | Best *transport/auth* engineering: OIDC/JWKS bearer, MCP tool annotations, engagement records — but scope is narrative-only text. |

### Group D — Burp-embedded extensions (wrap Burp's own engine)
| Server | Stars | 1-line takeaway |
|---|---|---|
| **six2dez/burp-ai-agent** | ~1.3k | 59 tools + redaction pipeline (STRICT/BALANCED), budget guard, AES-GCM secret storage, optional scope confinement — strongest *data-governance* design. |
| **BurpMCP-Ultra** (Cy-S3c) | ~131 | 149 tools, three-mode scope enforcement (off/warn/enforce), append-only audit log, oracle-based injection probes. |
| **swgee/BurpMCP** | ~51 | Minimal HITL: researcher right-clicks "Send to BurpMCP"; LLM resends/fuzzes. No auth, no scope. |
| **Cyreslab burpsuite-mcp** | ~8 | 100% mock/stub data — not functional. Scaffold only. |

### Group E — Agents / plugins (not servers)
| Server | Stars | 1-line takeaway |
|---|---|---|
| **0xSteph/pentest-ai-agents** | ~2.0k | 50 Claude Code subagents; Tier-1 advisory vs Tier-2 execution w/ approval gates + Scope Guard + detection parity. Soft (prompt-level) controls. |
| **PentestAgent/GHOSTCREW** | ~684 | MCP *host* driving per-tool MCP servers via `npx`; autonomous task trees, no scope/rate limits. |
| **appsecco/vulnerable-mcp-servers-lab** | ~263 | Deliberately-vulnerable *targets*, not a toolkit — our checklist of MCP vuln classes to avoid (path traversal, eval RCE, prompt injection, `MCP_ALLOWED_HOSTS=*`). |

**Meta-observations:**
- Star count ≠ safety. The two most-starred scanners (HexStrike 10.2k, GHOSTCREW) have the weakest guardrails.
- Only **3 of 23** implement any real scope enforcement in code: `akinabudu` (validate_target gate), `ptai` (host-locking + oracle), and the two Burp-Ultra/burp-ai-agent extensions (scope modes).
- The API/knowledge servers (Group B) are the safest and among the most useful, precisely because they never touch a target.

---

## 2. Common Tool Surface

Union of capabilities across the corpus, ranked by how many servers expose them:

| Capability | Prevalence | Typical binary/API | Notes |
|---|---|---|---|
| **Subdomain enumeration** | Very high (~18) | subfinder, amass, assetfinder, crt.sh | The universal entry point. crt.sh/CT-logs is a pure-API path needing no binary. |
| **Port scanning** | Very high (~16) | nmap, naabu, masscan, rustscan | Ranges from polite to internet-scale (masscan) — the most abuse-prone. |
| **HTTP probing / fingerprint** | Very high (~15) | httpx, whatweb | Liveness + tech stack + status/title. |
| **Template vuln scan** | High (~14) | nuclei | The single most-wrapped vuln engine; JSON output parses cleanly. |
| **Content/dir discovery + fuzzing** | High (~13) | ffuf, gobuster, feroxbuster, dirsearch, wfuzz | Wordlist-driven; needs SecLists. |
| **DNS enumeration/resolution** | High (~13) | dnsx, dnspython, shuffledns | Often done in-library (no binary). |
| **Web crawling** | Medium-high (~11) | katana, hakrawler, gospider | Endpoint discovery. |
| **Historical URLs** | Medium (~10) | gau, waybackurls, archive.org CDX | Pure-API — no binary required. |
| **SQLi testing** | Medium (~10) | sqlmap (or native heuristics) | Native reimplementations are consistently poor. |
| **XSS testing** | Medium (~9) | dalfox, xsser | |
| **Parameter discovery** | Medium (~8) | arjun, paramspider, x8 | |
| **OSINT / internet asset search** | Medium (~8) | Shodan, Censys, ZoomEye, theHarvester | API-key gated. |
| **Screenshotting** | Medium (~6) | gowitness, aquatone, Puppeteer | |
| **TLS/SSL analysis** | Medium (~6) | sslscan, tlsx, testssl.sh, sslyze | Partly doable with stdlib `ssl`. |
| **Security-header analysis** | Low-medium (~5) | native / axios | Trivial pure-stdlib. |
| **CVE / exploit lookup** | Low-medium (~5) | searchsploit, NVD, CVE intel | Mostly API. |
| **WAF fingerprint** | Low (~4) | wafw00f | |
| **JWT / GraphQL / CORS / secrets-in-JS** | Low (~4 each) | native heuristics | Cheap wins, mostly stdlib-doable. |
| **Report generation** | Medium (~7) | native | Markdown/HTML/SARIF. |
| **Program/scope intel (H1/Bugcrowd)** | Low (~4) | platform APIs | h1-brain, hackerone-mcp, akinabudu. |
| **Cloud / AD / binary / password-cracking** | Present but out-of-scope for bug-bounty | prowler, bloodhound, hashcat, ghidra | HexStrike/ptai kitchen-sink territory — deliberately excluded from our design. |

**Core "table stakes" set** (appears in nearly every serious server): subdomain enum → DNS resolve → port scan → HTTP probe → tech fingerprint → content discovery → crawl → nuclei vuln scan. This is the recon pipeline. A best-of-breed server must nail this loop and make it *safe*.

---

## 3. Architecture Patterns (what the good ones do)

**Execution model — three families:**
1. **Direct shell-out** (pd-tools, cyproxio): MCP tool → `spawn(argv)` → parse stdout. Simplest; correctness hinges on argv-array (no shell) usage.
2. **Two-process proxy → backend** (SlanyCukr, ExternalAttacker, HexStrike, ptai): thin FastMCP tool layer POSTs JSON to a local Flask/FastAPI backend that owns subprocess execution + parsing + caching. Cleaner separation, backend reusable outside MCP — but the backend becomes an unauthenticated RCE surface if bound beyond localhost (repeated failure).
3. **Engine-embedded** (Burp extensions): MCP server runs *inside* the tool's process (Montoya API), reusing its HTTP stack, scope, and scanner. No subprocess, no parsing brittleness — but not standalone.

**Command construction — the dividing line between safe and unsafe:**
- **Good:** `child_process.spawn('subfinder', ['-d', domain, '-json'])` / `asyncio.create_subprocess_exec([...])` — argv array, `shell=False`. Used by pd-tools, ExternalAttacker, dmontgomery40, FuzzingLabs. Structurally immune to shell metacharacter injection.
- **Bad:** `subprocess.run(f"nmap {target}", shell=True)` (Vasanthadithya) or `' '.join(cmd_parts)` (SlanyCukr) — direct injection.
- **Subtle-but-still-bad:** even with argv arrays, passing a free-form `args: string[]` straight through (cyproxio) or a value beginning with `-` (pd-tools) allows **argument/flag injection** — e.g., turning `sqlmap` into `--os-shell`, or injecting `-oN /etc/cron.d/x`. Argv-array is necessary but **not sufficient**; you must also validate that targets don't start with `-` and constrain flags to an allowlist.

**Async / long-running jobs:**
- Most servers run scans **synchronously** behind a timeout, blocking the stdio channel (pd-tools, cyproxio, ExternalAttacker). Bad for multi-minute nuclei runs.
- Best pattern: **job registry** — tool returns a `job_id` immediately; `get_job_status(job_id)` / `get_job_results(job_id)` poll. Seen in FuzzingLabs (`active_scans` dict), Vasanthadithya (`JOBS`), Burp extensions (task-based), Cyreslab (mock). Weakness in all: **in-memory, unbounded, non-persistent** — lost on restart, grows forever. Fix: bounded registry + optional SQLite persistence + TTL cleanup.

**Output parsing:**
- **Best:** consume the tool's native `-json`/`-jsonl`/`-oX` and map to typed structures, deduped and severity-mapped (SlanyCukr nuclei dedup on `template_id:matched_at`; FuzzingLabs nmap `-oX` XML; dmontgomery40 `fast-xml-parser`; pd-tools typed TS interfaces).
- **Worst:** return one raw stdout blob (cyproxio, ExternalAttacker). Compounded by "reject on non-zero exit" when many pentest tools **exit non-zero precisely when they find something** — so a successful scan surfaces as an error (cyproxio bug).

**Resources vs tools:**
- Underused. Only BurpMCP-Ultra (8 read-only resources: `burp://proxy/history`, `scanner/issues`, `sitemap`, `scope`) and Cyreslab expose MCP **resources**. Findings, scope, and engagement state are natural resources — read-only, cacheable, referenceable — and keep them out of the tool-call token budget.

**Persistence & reporting:**
- Best: SQLite engagement/findings DB with FTS (h1-brain, 0xSteph agents), engagement records per tool-run with `recordId` (dmontgomery40), multi-format export incl. SARIF 2.1.0 (ptai). Reporting is where API-wrapper hygiene meets scanner output.

**Auth/transport (mostly neglected, one exemplar):**
- dmontgomery40 is the only standalone scanner with real auth: bearer-token OIDC via JWKS (`jose`), token-introspection fallback, Origin validation, MCP tool annotations (`readOnlyHint`/`destructiveHint`). But it defaults auth **off** and binds `0.0.0.0` — the classic footgun.

---

## 4. Recurring Weaknesses & Gaps

Ranked by how consistently they appear:

1. **No scope/authorization enforcement (≈20/23).** The dominant failure. Almost every scanner will point nmap/nuclei/sqlmap/hydra at *any* host the LLM supplies. "Authorization" is a README disclaimer, not a code control. Combined with LLM-driven invocation and **prompt-injectable scan output** (scanned pages return attacker-controlled content that steers the agent), this is a genuine "scan a third party by accident" risk.

2. **Command / argument injection.** `shell=True` (Vasanthadithya, gokulapap heuristics aside), string-concat (SlanyCukr), disabled validation (ExternalAttacker's regex is commented out), and free-form `*_args` passthrough (cyproxio) or leading-`-` flag injection (pd-tools). Even the "safe" argv servers rarely guard against flag injection.

3. **No authentication on network-bound backends.** Flask/FastAPI backends on `:8888`/`:6991`/`:8000`/`:8181` with auth disabled/absent; if bound to `0.0.0.0` they're open remote command runners (HexStrike, ExternalAttacker, SlanyCukr, Vasanthadithya, swgee). appsecco lab literally demonstrates `MCP_ALLOWED_HOSTS=*`.

4. **No/weak rate limiting.** Mostly per-tool concurrency defaults, no global throttle. Aggressive modes escalate (SlanyCukr nuclei → concurrency 100 + intrusive; masscan internet-scale). Easy to get IP-banned or to DoS a target.

5. **No graceful degradation when binaries are absent.** ~29–150 binaries assumed on `PATH`, no version pinning, silent failures (HexStrike, cyproxio, pd-tools, SlanyCukr). A tool "exists" in the schema but errors cryptically at call time.

6. **Unstructured output & non-zero-exit mishandling.** Raw blobs, no size limits (memory OOM on big scans), and treating "found something" exit codes as failures.

7. **Capability overstatement.** README lists tools that are placeholders (gokulapap google_dorking/github_recon), mocks (Cyreslab), stubs (Vasanthadithya `pentest_target` = "coming soon"), or absent integrations (VulneraMCP's advertised-but-missing Burp). Erodes trust and misleads the agent.

8. **Dual-use / offensive-by-default arsenals.** Credential harvesting (Responder), C2 (Cobalt Strike/Sliver), exploit-dev, `--os-shell`, arbitrary RCE primitives — far beyond authorized bug-bounty recon, handed to an autonomous LLM (HexStrike, ptai, 0xSteph agents, cyproxio).

9. **No async job model.** Long scans block the stdio channel; no cancellation, no progress.

10. **Secrets hygiene.** Plaintext `.env`, committed `env.example`, API keys as argv (visible in `ps` — cyproxio MobSF), no rotation. Only burp-ai-agent does AES-GCM-at-rest.

11. **In-memory, unbounded state.** Job/scan dicts lost on restart, grow without cleanup.

12. **No audit trail.** Only BurpMCP-Ultra (append-only JSONL) and dmontgomery40/ptai record what was run against what.

---

## 5. Differentiation Opportunities

Concrete ways to be **better and safer** than everything above:

1. **Scope as a hard, mandatory, central gate — not narrative text.** A single choke-point every active tool must pass through. Adopt akinabudu's `validate_target` idea but make it *impossible to bypass* (enforced in the execution layer, not trusted to each tool), plus ptai's host-locking (never feed third-party URLs scraped from a page into an attack tool). Three modes (`off`/`warn`/`enforce` like BurpMCP-Ultra), **defaulting to `enforce`**.

2. **Works out-of-the-box with zero binaries.** No competitor does this. Every core recon capability has a **pure-Python-stdlib fallback** (sockets, `ssl`, `http.client`, `urllib`, `concurrent.futures`) so the server is useful the moment it's installed, and *upgrades* to subfinder/httpx/nuclei/ffuf when present. This eliminates the #5 weakness entirely and makes the tool count *honest*.

3. **Capability introspection tool.** A `capabilities()` tool that reports, per feature, whether it's running in `native` (stdlib) or `enhanced` (binary detected) mode, with the exact binary/version. Kills capability-overstatement; the agent knows what it actually has.

4. **Flag-injection-proof execution.** Argv arrays only, plus: targets validated against a strict grammar (must be a hostname/IP/URL, must not start with `-`), and per-tool **flag allowlists** — the LLM never passes free-form `*_args`. Structured params only.

5. **Read-only-first, destructive-gated.** Split tools into `recon` (passive/read-only, `readOnlyHint`) and `active` (sends payloads, `destructiveHint`). Active tools require scope-enforce to pass *and* an explicit engagement to be open. No sqlmap `--os-shell`, no credential harvesting, no C2 — bug-bounty recon + safe vuln detection only.

6. **Rate limiting as a global token bucket**, per-target, not just per-tool concurrency. Configurable RPS with a conservative default (e.g. 10 rps/host), automatic backoff on 429/rate-limit signals (ptai's RateLimitDetector idea).

7. **Findings & scope as MCP resources**, not tool spam. `engagement://scope`, `engagement://findings`, `engagement://targets` — read-only, cacheable, out of the tool token budget.

8. **Prompt-injection hardening on tool output.** Wrap all scanned/fetched content in a clear trust boundary and truncate to size caps (burp-ai-agent's redaction gate + BurpMCP-Ultra size caps). Scanned page content is *data*, never *instructions*.

9. **Async job model done right:** bounded registry + SQLite persistence + TTL cleanup + cancellation. Survives restart; no unbounded growth.

10. **Append-only audit log** (JSONL) of every active action: tool, target, params, scope-decision, timestamp, engagement ID. Non-negotiable for an authorized-testing tool.

11. **Honest, safe, mid-sized surface (~15 tools)** rather than 92/149/300 mostly-placeholder tools. Every tool functional, tested, and documented.

---

## 6. Recommended Design for OUR Server

### 6.1 Stack
- **Language:** Python 3.11+. Rationale: richest stdlib for the pure-Python fallbacks (`socket`, `ssl`, `http.client`, `urllib`, `ipaddress`, `concurrent.futures`, `sqlite3`), and the security-tool ecosystem is Python-native.
- **SDK:** Official `mcp` / **FastMCP** (`@mcp.tool()` decorators + MCP resources). Async throughout (`asyncio`, `asyncio.create_subprocess_exec`).
- **Transport:** **stdio by default** (zero attack surface, matches Claude Code/Desktop). Optional Streamable HTTP behind **mandatory bearer auth + `127.0.0.1` bind + Origin allowlist** — and if HTTP is selected, auth cannot be disabled (fix dmontgomery40's footgun). No SSE.
- **Packaging:** single `uv`/`pip`-installable package, no binaries required; optional Docker image that bundles subfinder/httpx/nuclei/naabu/ffuf for "enhanced" mode.
- **Dependencies:** keep runtime deps minimal (`mcp`, `httpx` optional-but-recommended for async HTTP; everything else stdlib). No aiohttp-heuristic vuln reimplementation like gokulapap.

### 6.2 Execution model
- Single-process (no separate Flask backend — avoids the unauthenticated-backend class of bug). A central `Executor` with two paths per capability:
  - `native`: pure-stdlib implementation.
  - `enhanced`: `asyncio.create_subprocess_exec(argv_list)` (never `shell=True`) when the binary is detected at startup.
- **Binary detection at startup:** probe `PATH` (`shutil.which`) + `--version`, cache a `ToolRegistry` mapping capability → {mode, binary, version}. Surfaced via `capabilities()`.
- **Command safety:** targets validated by a strict validator (`validate_target`) before any execution; flags come only from typed params mapped through per-tool allowlists; no user/LLM string reaches a shell.

### 6.3 The scope/authorization guardrail model

The heart of the differentiation. A mandatory pre-execution gate no active tool can skip.

```
Engagement (in-memory + SQLite)
  ├─ id, name, created_at, authorized_by (free text attestation)
  ├─ scope_mode: enforce (default) | warn | off
  ├─ in_scope:   [ domains (wildcards ok), CIDRs, exact hosts, URLs ]
  ├─ out_of_scope: [ same shapes; takes precedence ]
  └─ rate_limit: rps_per_host (default 10), max_concurrency
```

- **`validate_target(target, engagement)`** is called inside the `Executor`, not by individual tools — so a new tool physically cannot forget it. Returns `ALLOW` / `DENY` / `WARN`.
- **Default-deny in `enforce` mode:** a target must match `in_scope` and not match `out_of_scope`. RFC1918/loopback/link-local/metadata-IP (169.254.169.254) are **blocked unless explicitly whitelisted** in the engagement (prevents internal-SSRF-style scanning — a gap in cyproxio et al.).
- **Host-locking (ptai pattern):** URLs discovered *from scanned content* (crawl results, JS endpoints) are NOT auto-fed into active tools; they must independently pass scope validation. Third-party assets are dropped.
- **No engagement ⇒ no active tools.** Passive/read-only recon against a single explicitly-supplied host may run, but anything sending payloads requires an open engagement with matching scope.
- **Audit:** every active call appends to `~/.bbmcp/audit.jsonl` with the scope decision.

### 6.4 Proposed MCP tools (~16)

Grouped by risk tier. `RO` = read-only/passive, `ACT` = active (scope-gated).

**Engagement & meta (RO)**
| Tool | Purpose |
|---|---|
| `capabilities` | Report per-capability mode (native vs enhanced), detected binaries + versions, and scope status. |
| `create_engagement` | Open a scoped engagement (in/out-of-scope lists, scope_mode, rate limit, authorization attestation). |
| `set_scope` | Update in-scope / out-of-scope entries and scope_mode for the active engagement. |
| `validate_target` | Explicitly check whether a host/IP/URL is in scope (the same gate tools use internally) — lets the agent pre-check before acting. |

**Passive recon (RO — no packets to target, or benign single requests)**
| Tool | Purpose |
|---|---|
| `enum_subdomains` | Subdomain discovery: native via crt.sh CT-log API (+ optional DNS brute of a small builtin list); enhanced via subfinder/amass. |
| `resolve_dns` | Resolve A/AAAA/MX/NS/TXT/CNAME: native via stdlib socket + optional `dnspython`; enhanced via dnsx. |
| `historical_urls` | Fetch archived URLs: native via Wayback CDX + crt.sh (pure API, no binary); enhanced via gau/waybackurls. |
| `osint_lookup` | Shodan/Censys host lookup (API-key gated; degrades to "unavailable" cleanly if no key) + CT-log/ASN data. |

**Active recon (ACT — sends traffic, scope-gated)**
| Tool | Purpose |
|---|---|
| `scan_ports` | TCP connect scan of a host/port-range: native via `asyncio` socket connect (bounded, rate-limited); enhanced via naabu/nmap (service detection). |
| `probe_http` | Liveness + status/title/redirects/server header for a URL list: native via `httpx`/stdlib; enhanced via ProjectDiscovery httpx. |
| `fingerprint_tech` | Detect web technologies from headers/body/cookies/favicon-hash: native heuristic ruleset; enhanced via httpx/whatweb. |
| `analyze_tls` | Cert chain, expiry, SANs, protocol/cipher support: native via stdlib `ssl`; enhanced via tlsx/sslscan. |
| `check_security_headers` | Score HTTP security headers (CSP/HSTS/X-Frame/etc.) against OWASP: pure native. |
| `discover_content` | Directory/file brute-forcing against a base URL with a chosen wordlist: native async fetcher + bundled small wordlist; enhanced via ffuf/feroxbuster (+ SecLists). |
| `crawl_site` | Crawl for endpoints/links/JS (scope-locked, depth-limited): native via httpx + HTML/JS URL extraction; enhanced via katana. Discovered URLs are NOT auto-attacked. |
| `scan_vulnerabilities` | Template-based vuln scan: enhanced via nuclei (`-jsonl`, deduped, severity-mapped); native fallback = a small curated set of safe, high-signal checks (exposed `.git`, security-header misconfig, default files, CORS misconfig, known-path probes). Clearly labels which engine ran. |

**Findings & reporting (RO)**
| Tool | Purpose |
|---|---|
| `record_finding` / `get_findings` | Add to / query the engagement findings store (SQLite); dedup + severity. |
| `generate_report` | Produce a Markdown / JSON / SARIF 2.1.0 report from findings for the engagement. |

**Long-running jobs (cross-cutting):** the heavier active tools (`scan_ports`, `discover_content`, `scan_vulnerabilities`, `crawl_site`) return a `job_id` immediately and are polled via **`get_job`** (status/partial results) with a **`cancel_job`**. Job registry is bounded + SQLite-persisted + TTL-cleaned.

**MCP Resources (read-only, out of tool token budget):**
- `engagement://scope` — current in/out-of-scope + mode.
- `engagement://findings` — accumulated findings.
- `engagement://jobs` — active/recent jobs.
- `capabilities://tools` — native/enhanced status snapshot.

### 6.5 Handling missing external binaries

Design principle: **every core capability degrades to a functional native mode; binaries are an accelerator, never a hard dependency.**

| Capability | Native (stdlib) fallback | Enhanced (if binary present) |
|---|---|---|
| Subdomain enum | crt.sh CT-log HTTP API + small builtin DNS brute list | subfinder, amass |
| DNS resolve | `socket.getaddrinfo`, `socket.gethostbyaddr` (+ optional dnspython for record types) | dnsx |
| Historical URLs | Wayback CDX API, crt.sh — pure HTTP, no binary | gau, waybackurls |
| Port scan | `asyncio` TCP-connect scanner, rate-limited, bounded ranges | naabu, nmap (service/OS) |
| HTTP probe | `httpx`/stdlib requests, follow redirects, grab title/headers | ProjectDiscovery httpx |
| Tech fingerprint | header/cookie/body/favicon-hash rules | httpx tech-detect, whatweb |
| TLS analysis | stdlib `ssl.SSLContext` + `getpeercert()` | tlsx, sslscan, testssl |
| Security headers | pure Python scoring | (native is best-in-class already) |
| Content discovery | async fetcher + bundled mini-wordlist | ffuf, feroxbuster + SecLists |
| Crawl | httpx + regex/HTML link + JS-endpoint extraction | katana |
| Vuln scan | curated safe checks (.git exposure, CORS, default files, header misconfig) | **nuclei** (the real engine) |
| OSINT | direct Shodan/Censys REST (API-key) | — |

**Rules:**
- Detect at startup; **never** silently fail at call time. If a capability is requested and neither native nor enhanced is available (e.g., OSINT without an API key), return a **structured `unavailable` result** naming exactly what's missing and how to enable it — not a stack trace.
- `capabilities()` always tells the agent the truth, so the LLM can plan around what's actually present.
- Version-check enhanced binaries and record the version in output + audit log (parsing is version-sensitive).

### 6.6 Structured output shape

Uniform envelope for **every** tool (fixes raw-blob + non-zero-exit + size-cap problems at once):

```json
{
  "tool": "scan_ports",
  "engine": "native",                     // "native" | "enhanced:nmap@7.94"
  "engagement_id": "eng_...",
  "target": "example.com",
  "scope_decision": "allow",              // allow | warn | (deny -> tool never ran)
  "status": "completed",                  // completed | running | error | unavailable | denied
  "job_id": "job_...",                    // present for async tools
  "started_at": "...", "finished_at": "...",
  "summary": { "open_ports": 3, "hosts": 1 },   // small, always safe to read
  "findings": [
    {
      "id": "f_...",
      "type": "open_port",
      "severity": "info",                 // info|low|medium|high|critical
      "target": "example.com:443",
      "title": "443/tcp open (https)",
      "evidence": "...",                  // truncated to size cap
      "confidence": "confirmed",          // confirmed | probable | heuristic
      "source_engine": "native",
      "references": []
    }
  ],
  "truncated": false,                     // true if output hit size cap
  "raw_ref": "job://.../raw",             // pointer to full raw output (resource), not inlined
  "errors": [],
  "warnings": ["binary 'nmap' not found; used native TCP-connect scan"]
}
```

Key properties:
- **`status` is explicit** — a scanner finding vulns (non-zero exit) is `completed`, not `error` (fixes cyproxio's bug).
- **`summary` is always small**; full findings are paginated; **raw output is a resource reference**, never dumped inline (fixes context-blowout + OOM).
- **`confidence` + `source_engine`** on every finding — the agent (and the human) knows whether it's a confirmed nuclei hit or a native heuristic guess.
- **`scope_decision` recorded inline** so the audit trail is self-describing.
- Nuclei-style **dedup** on `(type, target, template_id)`; severities normalized to a single scale across engines.

---

### TL;DR of the blueprint
Build a **Python/FastMCP, stdio-first** server that (1) exposes a **~16-tool honest recon + safe-vuln-detection surface**, (2) **runs fully on the stdlib out of the box** and transparently upgrades to subfinder/httpx/nuclei/naabu/ffuf when present (reported via `capabilities()`), (3) enforces a **mandatory, default-deny scope gate + rate limiter + private-IP block** that no active tool can bypass, (4) uses **argv-array execution with target/flag validation** (no shell, no free-form args), (5) runs heavy scans as **persisted, cancellable async jobs**, (6) returns a **uniform structured envelope** with explicit status, confidence, engine provenance, and resource-referenced raw output, and (7) writes an **append-only audit log** — deliberately excluding C2/exploit-dev/credential-harvesting to stay within authorized bug-bounty scope. This directly fixes the scope, injection, degradation, output, and honesty failures that recur across all 23 surveyed servers, while borrowing the best ideas: akinabudu's scope model, ptai's host-locking + oracle confidence, dmontgomery40's auth/annotations, burp-ai-agent's redaction/audit, and h1-brain's report-intel persistence.
