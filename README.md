# 🌙 MoonMCP

**A scope-aware bug-bounty & reconnaissance MCP server that works out of the box on the Python standard library — and augments itself with your favourite CLI tools when they're present.**

MoonMCP exposes a curated set of reconnaissance, fingerprinting and OSINT
capabilities to any [Model Context Protocol](https://modelcontextprotocol.io)
client (Claude Desktop, Claude Code, Cursor, …), so an AI agent can map a target's
attack surface **safely and within an authorised scope**.

> ⚖️ **Authorised testing only.** MoonMCP is for security research on assets you
> own or are explicitly permitted to test (e.g. a bug-bounty program's in-scope
> targets). You are responsible for staying within scope and the law.

---

## Why another recon MCP server?

Before writing a line of code, we surveyed the ecosystem: a fan-out research pass
discovered **161 candidate projects** and deep-read **23 confirmed** bug-bounty /
offensive-security MCP servers (ProjectDiscovery's `pd-tools-mcp`, `HexStrike AI`,
`ExternalAttacker-MCP`, `gokulapap/bugbounty-mcp-server`,
`SlanyCukr/bugbounty-mcp-server`, `VulneraMCP`, `akinabudu/bug-bounty-mcp`,
`cyproxio/mcp-for-security`, several `pentest-mcp` variants, `BurpMCP`, and the
HackerOne-platform integrations, among others). The full survey and the design
blueprint it produced are in [`docs/RESEARCH.md`](docs/RESEARCH.md). Three patterns
stood out:

| Observation across the ecosystem | MoonMCP's answer |
| --- | --- |
| **Almost everything is a thin CLI wrapper.** They shell out to `subfinder`, `amass`, `nmap`, `masscan`, `httpx`, `nuclei`, `sqlmap`, `ffuf`, `gobuster`, … and are **useless until you install a pile of Go/native binaries.** | **Stdlib-first.** Every core tool is implemented on the Python standard library, so MoonMCP is useful the moment it starts — no external binaries required. |
| **Kitchen-sink surfaces** (some expose 40–50 tools) that assume a fully-loaded pentest box and offer little safety. | **A focused, ~33-tool surface** covering the recon workflow end-to-end, each with structured JSON output. |
| **No authorization model.** Point-and-scan primitives with no notion of "is this target in scope?" | **Scope-first.** Every packet-sending tool is gated by an authorization scope; intrusive scans are opt-in and rate-limited. |

MoonMCP's design principles:

* **🔋 Works out of the box** — zero required dependencies beyond the MCP SDK.
* **🧩 Augments, never depends** — detects and wraps `nuclei`/`httpx`/`subfinder`/`nmap`/… when installed, degrades gracefully when not.
* **🛡️ Scope-first & safe by default** — an authorization guardrail on every active tool, rate limiting, and an intrusive-tools switch.
* **📦 Structured output** — everything returns clean JSON, not scraped console text.

---

## Tool surface

MoonMCP exposes **33 tools**, **2 resources** and **1 guided prompt**, grouped by how much they touch the target:

### 🟢 Meta / scope
| Tool | Purpose |
| --- | --- |
| `server_status` | Report config, detected enhancers and external CLIs. |
| `scope_list` / `scope_add` / `scope_exclude` / `scope_remove` | Manage the authorization scope at runtime. |

### 🔵 Passive OSINT (never touches the target)
| Tool | Purpose |
| --- | --- |
| `enumerate_subdomains` | Passive subdomain enum via crt.sh, HackerTarget, AnubisDB, AlienVault OTX. |
| `wayback_urls` | Historical URLs from the Internet Archive (flags interesting endpoints). |
| `cve_lookup` / `cve_search` | Query the NVD for a CVE by ID or by keyword (e.g. a product+version). |
| `host_intel` | IP exposure via Shodan InternetDB (free) or the full Shodan API. |
| `email_security` | SPF / DMARC / DKIM / CAA posture with an A–F grade (DNS-based). |
| `jwt_analyze` | Decode a JWT and flag `alg:none`, weak HS*, missing expiry, key-injection (no traffic). |

### 🟡 Active — light (benign, in-scope requests)
| Tool | Purpose |
| --- | --- |
| `dns_lookup` | Resolve A/AAAA + MX/NS/TXT/CNAME/SOA/CAA (via dnspython **or DNS-over-HTTPS**, no dep needed) and reverse PTR. |
| `http_probe` | Structured HTTP(S) probe: status, headers, timing, redirect chain, title. |
| `tls_inspect` | Certificate subject/issuer/validity + **Subject Alt Names** (sibling hosts). |
| `analyze_headers` | Security-header audit with an A–F grade; flags leaks and risky cookies. |
| `fingerprint` | Technology detection: server, CDN/WAF, language, framework, CMS, JS libs. |
| `well_known` | Fetch & parse robots.txt, sitemap.xml, security.txt, humans.txt. |

### 🕸️ Web-app checks (light active, in-scope, structured findings)
| Tool | Purpose |
| --- | --- |
| `crawl` | Bounded depth-1 crawl → internal links, forms+inputs, JS/asset URLs, parameters, external hosts, emails. |
| `extract_secrets` | Scan a page **and its JavaScript** for exposed keys/tokens (AWS, GitHub, Slack, Stripe, private keys, JWTs) — redacted. |
| `cors_audit` | CORS misconfig: origin reflection, `null` origin, prefix/suffix bypass — worse with credentials. |
| `graphql_check` | Discover GraphQL endpoints and test whether **introspection** is enabled. |
| `waf_detect` | Fingerprint WAF/CDN (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, F5, …). |
| `takeover_check` | Subdomain-takeover detection over a 40+ provider fingerprint DB (S3, GH Pages, Heroku, Azure, …). |
| `open_redirect` | Inject a canary into common redirect params (url, next, returnTo, …) — Location / meta / JS. |
| `vcs_exposure` | Confirm exposed `.git`/`.svn`/`.env`/`.DS_Store` by content signature; extract git remote + commit log. |

### 🟠 Active — intrusive (gated by `MOONMCP_ALLOW_INTRUSIVE`)
| Tool | Purpose |
| --- | --- |
| `port_scan` | Unprivileged TCP connect-scan (`top` set or a custom range), optional banners. |
| `content_discovery` | Probe for sensitive paths (admin, `.git`, `.env`, backups, API docs, …). |
| `http_methods` | Enumerate allowed methods + probe risky ones (TRACE/PUT/DELETE/PATCH → XST / write-enabled). |
| `vuln_scan` | Run a `nuclei` template scan (requires nuclei installed). |

### 🔗 Orchestration & external tools
| Tool | Purpose |
| --- | --- |
| `recon_target` | One-shot passive+light sweep (subdomains → DNS → TLS → HTTP → headers → fingerprint → email security). |
| `external_tools` | List known security CLIs and whether each is installed + its native fallback. |
| `run_scanner` | Run an installed CLI (`subfinder`, `httpx`, `nuclei`, `nmap`, `ffuf`, …); JSONL auto-parsed. |

**Resources:** `moonmcp://scope`, `moonmcp://capabilities`
**Prompt:** `recon_methodology` — a guided, scope-safe recon playbook.

---

## Quickstart

Requires **Python 3.10+**.

```bash
# with uv (recommended)
uv tool install --from . moonmcp        # or: uvx --from . moonmcp
# or with pip
pip install .

# sanity check (prints detected capabilities, does not start the server)
moonmcp --check
```

### Add to an MCP client

Claude Desktop / Claude Code (`claude_desktop_config.json` or `.mcp.json`):

```json
{
  "mcpServers": {
    "moonmcp": {
      "command": "moonmcp",
      "env": {
        "MOONMCP_SCOPE": "*.example.com, 203.0.113.0/24",
        "MOONMCP_ALLOW_INTRUSIVE": "0"
      }
    }
  }
}
```

See [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json) for a fuller example.

Then, in the client: *"Using MoonMCP, run recon on example.com"* — the agent will
call `scope_add`, then the passive/light tools, and summarise the attack surface.

---

## Configuration

All configuration is via environment variables (set them in your MCP client's `env` block):

| Variable | Default | Description |
| --- | --- | --- |
| `MOONMCP_SCOPE` | *(empty)* | Comma/newline-separated in-scope entries: domains, `*.wildcards`, hosts, IPs, CIDRs. |
| `MOONMCP_SCOPE_EXCLUDE` | *(empty)* | Out-of-scope entries that always override the allowlist. |
| `MOONMCP_ENFORCE_SCOPE` | `1` | When on, active tools refuse targets not in scope. |
| `MOONMCP_BLOCK_PRIVATE` | `1` | SSRF guard: hard-block private/loopback/link-local/reserved IPs (incl. cloud metadata). Set `0` for authorised internal-network testing. |
| `MOONMCP_ALLOW_INTRUSIVE` | `1` | Gate for `port_scan`, `content_discovery`, `vuln_scan`. |
| `MOONMCP_RATE_LIMIT` | `20` | Max outbound requests/sec (token bucket; `0` = unlimited). |
| `MOONMCP_MAX_CONCURRENCY` | `20` | Max concurrent outbound connections. |
| `MOONMCP_TIMEOUT` | `10` | Default request timeout (seconds). |
| `MOONMCP_USER_AGENT` | `MoonMCP/0.1 …` | User-Agent for HTTP probing. |
| `MOONMCP_ALLOW_EXTERNAL_TOOLS` | `1` | Allow shelling out to installed CLIs. |
| `MOONMCP_EXTERNAL_TIMEOUT` | `300` | Hard ceiling on any external CLI run (seconds). |
| `MOONMCP_SHODAN_API_KEY` | *(none)* | Enables the full Shodan API (else free InternetDB). |
| `MOONMCP_NVD_API_KEY` | *(none)* | Raises the NVD CVE-lookup rate limit. |

---

## The scope model

Scope is MoonMCP's core safety guardrail. Entries are matched like a bug-bounty program:

| Entry | Matches |
| --- | --- |
| `example.com` | the apex **and** every subdomain |
| `*.example.com` | subdomains only (not the apex) |
| `api.example.com` | that exact host (and deeper labels under it) |
| `203.0.113.10` | a single IP |
| `10.0.0.0/8` | a CIDR range (IPv4 or IPv6) |

**Exclusions always win** over inclusions, so `scope_add example.com` +
`scope_exclude admin.example.com` authorises everything under `example.com` except
`admin.example.com`. When enforcement is on and the scope is empty, active tools
refuse to run until you authorise a target — a deliberate "fail closed" default.

Passive OSINT tools also scope-check the apex, so MoonMCP only enumerates assets
you've declared authorised.

**Defence in depth.** Beyond the allowlist, MoonMCP:

* **Blocks private/reserved IPs** (RFC1918, loopback, link-local incl. the
  `169.254.169.254` cloud-metadata endpoint) by default — an SSRF guard no active
  tool can bypass, even if a broad CIDR was added. Flip `MOONMCP_BLOCK_PRIVATE=0`
  for authorised internal engagements.
* **Re-checks redirects** — the HTTP client refuses to follow a `Location` that
  leaves the scope, and reports it as `redirect_blocked` instead.
* **Scope-checks external-CLI targets** — `run_scanner` extracts and validates the
  host/URL from its args, not just the optional `target` field.

---

## Augmenting with external CLIs

MoonMCP has native, stdlib implementations for the whole recon workflow, but it
gets sharper when best-in-class tools are on `PATH`. It auto-detects and can run:

`subfinder`, `httpx`, `nuclei`, `naabu`, `nmap`, `katana`, `ffuf`, `gau`, `dnsx`,
`amass`, `waybackurls`.

If a tool is missing, MoonMCP returns a clear note and the **native fallback** to
use instead — nothing errors out. Call `external_tools` to see what's available.

> Note: the ProjectDiscovery `httpx` binary and the Python `httpx` library share a
> name. MoonMCP detects and ignores the Python shim so it won't be mistaken for the
> scanner.

---

## Architecture

```
moonmcp/
├── server.py        # FastMCP server: 33 tools, 2 resources, 1 prompt
├── scope.py         # ScopeManager — the authorization guardrail
├── config.py        # env-driven Settings
├── context.py       # shared Settings + Scope + rate Governor + HttpClient
├── net/             # stdlib networking (async via asyncio.to_thread)
│   ├── http.py      #   urllib-based HTTP client w/ redirect tracing + rate limit
│   ├── dns.py       #   getaddrinfo + DNS-over-HTTPS (+ optional dnspython)
│   ├── tls.py       #   ssl-based certificate inspection
│   ├── ports.py     #   asyncio TCP connect-scan
│   └── ratelimit.py #   token-bucket + concurrency governor
├── recon/           # subdomains, fingerprint, headers, wayback, content, crawl, secrets
├── web/             # cors, graphql, waf, jwt, methods, subdomain takeover
├── intel/           # cve (NVD), shodan (InternetDB / API), email (SPF/DMARC/DKIM/CAA)
└── external/        # optional CLI detection + safe invocation
```

Everything is async and shares one rate limiter, so recon traffic stays polite.
Blocking stdlib calls are wrapped with `asyncio.to_thread`; port scanning uses
native asyncio streams.

---

## Development

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev,enhanced]"
pytest -q          # 50 tests: scope logic, parsers, web-app checks, and local-server integration
ruff check .
```

Tests are fully offline — network-dependent parsers are covered with fixtures, and
the HTTP/port/content tools are exercised against a local `http.server`.

---

## Ethics & legal

MoonMCP is a defensive/authorised-research tool. Only use it against systems you
own or have explicit written permission to test (e.g. an in-scope bug-bounty
target). Respect program rules, rate limits and the law. The authors accept no
liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
