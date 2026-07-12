# 🌙 MoonMCP

**A scope-aware bug-bounty & reconnaissance MCP server that works out of the box on the Python standard library — and augments itself with your favourite CLI tools when they're present.**

[![CI](https://github.com/Moonwuk/MoonMcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Moonwuk/MoonMcp/actions/workflows/ci.yml)

MoonMCP exposes a curated set of reconnaissance, fingerprinting, OSINT and
**detection** capabilities to any [Model Context Protocol](https://modelcontextprotocol.io)
client (Claude Desktop, Claude Code, Cursor, …), so an AI agent can map a target's
attack surface **safely and within an authorised scope**: web + OSINT recon
(multi-engine search, a page reader, subdomains, wayback, CVE/Shodan), web-app
detectors (CORS, GraphQL introspection + batch/BOLA, WebSocket/CSWSH, secrets,
exposed-`.git` history forensics, injection/SQLi/SSRF/SSTI, datastore exposure),
behavioural infrastructure mapping, offline knowledge bases, and a **persistent,
cross-agent memory hub with a typed knowledge graph** so findings are remembered and
built upon. Every tool is **detection-only** — leads to verify, with weaponisation
delegated to sqlmap/Strix under human confirmation.

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
| **Kitchen-sink surfaces** (some expose 40–50 tools) that assume a fully-loaded pentest box and offer little safety. | **A focused tool surface** covering the recon workflow end-to-end, each with structured JSON output, plus offline knowledge bases (injections, techniques, privilege escalation, server-side vulns, WAF). |
| **No authorization model.** Point-and-scan primitives with no notion of "is this target in scope?" | **Scope-first.** Every packet-sending tool is gated by an authorization scope; intrusive scans are opt-in and rate-limited. |

MoonMCP's design principles:

* **🔋 Works out of the box** — zero required dependencies beyond the MCP SDK.
* **🧩 Augments, never depends** — detects and wraps `nuclei`/`httpx`/`subfinder`/`nmap`/… when installed, degrades gracefully when not.
* **🛡️ Scope-first & safe by default** — an authorization guardrail on every active tool, rate limiting, and an intrusive-tools switch.
* **📦 Structured output** — everything returns clean JSON, not scraped console text.

---

## Tool surface

MoonMCP exposes **162 tools**, **11 resources** and **9 operator prompts**, grouped by how much they touch the target:

### 🟢 Meta / scope
| Tool | Purpose |
| --- | --- |
| `server_status` | Report config, active program, detected enhancers and external CLIs. |
| `tool_catalog` | Self-describing **map of all tools** grouped by family, each tagged `scope_gated` / `intrusive`, plus the recommended recon→report workflow — call it second to orient. |
| `scope_list` / `scope_add` / `scope_exclude` / `scope_remove` | Manage the authorization scope at runtime. |
| `program_add` / `program_use` / `program_list` / `program_remove` | **Bug-bounty program profiles.** Each program carries its own scope **and its own identifying header** (e.g. `X-HackerOne-Research: <handle>`) + optional User-Agent; activating one swaps in its scope and auto-attaches its header/UA to every in-scope request. Persist across restarts via `MOONMCP_STATE_DIR`. |
| `auth_set` / `auth_clear` | Set the engagement auth context (bearer / cookie / basic / headers) so the web tools test the **authenticated** surface — merged into every in-scope request only. |
| `oast_configure` / `oast_selfhost` / `oast_generate` / `oast_poll` / `oast_list` | Out-of-band **callback** canaries to confirm **blind** vulns (blind SSRF/XXE/RCE/SQLi, blind XSS): point at an interactsh/Collaborator (`oast_configure`) **or start the built-in catcher** (`oast_selfhost`, stdlib — no third party), mint a canary URL, plant it, poll for the callback. |
| `audit_log` | Read the session **audit trail** — one record per scope decision (allow / deny / SSRF-block) and external command (also on `audit://recent`, persisted via `MOONMCP_AUDIT_LOG`). |

### 🔵 Passive OSINT (never touches the target)
| Tool | Purpose |
| --- | --- |
| `web_search` | Search the internet (keyless) → structured title / URL / snippet results. **Multi-engine & resilient**: tries DuckDuckGo HTML → DDG Lite → Bing and returns the first that answers (so one engine failing doesn't blind the search); dedupes by URL; `site=` scopes to one domain. Passive — queries a search engine, not the target. |
| `web_read` | Fetch a **public** page and return clean readable content — title, description, main text (scripts/styles/nav stripped), outbound links, word count. The OSINT *reader* that pairs with `web_search`. Not target-scoped (reads third-party research), but the block-private SSRF guard still refuses internal/metadata IPs and no engagement auth is sent; returned text is **untrusted**. |
| `search_dorks` | Generate ready-to-run **Google/Bing dorks** for a target (exposed files, login panels, config/secrets, dir listings, code leaks, SSRF params). |
| `enumerate_subdomains` | Passive subdomain enum via crt.sh, HackerTarget, AnubisDB, AlienVault OTX. |
| `wayback_urls` | Historical URLs from the Internet Archive (flags interesting endpoints). |
| `cve_lookup` / `cve_search` | Query the NVD for a CVE by ID or by keyword (e.g. a product+version). |
| `host_intel` | IP exposure via Shodan InternetDB (free) or the full Shodan API. |
| `ip_intel` | Map an IP → ASN, org, ISP, cloud/CDN provider, hosting flag, reverse DNS, geo. |
| `reverse_ip` | Other domains co-hosted on the same IP (reverse-IP lookup). |
| `cloud_buckets` | Enumerate cloud storage buckets (S3 / GCS / Azure Blob): permutate names from a keyword and probe which exist and which are anonymously **listable**. |
| `email_security` | SPF / DMARC / DKIM / CAA posture with an A–F grade (DNS-based). |
| `jwt_analyze` | Decode a JWT and flag `alg:none`, weak HS*, missing expiry, key-injection (no traffic). |
| `jwt_alg_confusion` | **JWT algorithm-confusion forgery** — re-signs a captured RS/ES token as HS256/384/512 using the **public key's PEM text** as the HMAC secret (`kid` preserved). If the verifier reuses the same key material for both algorithm families, the forged token validates under the public key alone — full forgery without the private key. No traffic, offline. |
| `deserialize_fingerprint` | **Deserialization-format fingerprint** (Freddy-lite) — 100% passive byte/base64 signature scan of an already-captured cookie/header/field value: Java native serialization (`ACED0005`/`rO0AB...`), .NET ViewState (LosFormatter `FF01`), PHP `serialize()` objects, Python pickle, Ruby `Marshal`, Fastjson/Jackson polymorphic JSON (`@type`/`@class`). Reports the format; never invokes a gadget chain (→ ysoserial/PHPGGC/ViewGen via Strix). No traffic. |

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
| `analyze_js` | Deep-extract the hidden API surface from a page **and its JavaScript** (LinkFinder-style) — absolute/relative endpoints a UI crawl misses, plus source maps (`.map`). |
| `parse_openapi` | Parse an OpenAPI/Swagger spec (URL or pasted) → full endpoint/param/method inventory, servers, security schemes, and flags (operations with **no** security). |
| `extract_secrets` | Scan a page **and its JavaScript** for exposed keys/tokens (AWS, GitHub, Slack, Stripe, private keys, JWTs) — redacted. |
| `cors_audit` | CORS misconfig: origin reflection, `null` origin, prefix/suffix bypass — worse with credentials. |
| `access_control_check` | Replay a request as **user A (auth) vs user B vs anonymous** and diff the responses → broken-access-control / IDOR signal (the #1 payout class; set `auth_set` first). |
| `authz_probe` | Function/object-level authorization: replay a privileged/admin action as a lower-priv or anonymous user → BFLA / BOLA. |
| `response_leak_probe` | Drives the OTP / reset / verify flow and detects the out-of-band secret (token/OTP) returned **in-band** in the response (account-takeover primitive). |
| `reset_poison_probe` | **Password-reset poisoning** via `Host` / `X-Forwarded-Host` — the reset link is built to point at an attacker host. |
| `path_bypass_probe` | 401/403 → 2xx **path-normalization ACL bypass** (`/admin/./`, `%2e`, trailing dot, case, `..;/`). |
| `crlf_probe` | **CRLF injection** → response splitting / header injection (Set-Cookie / redirect smuggling). |
| `oauth_probe` | **OIDC discovery** recon — flags implicit grant, missing/`plain` PKCE, `none`/HS256 signing, `http` issuer, issuer↔jwks mismatch. |
| `oauth_redirect_probe` | OAuth **`redirect_uri` validation bypass** (prefix/suffix/subdomain/open-redirect chaining). |
| `recover_sourcemaps` | Recover the original app source from exposed `.js.map` **sourcemaps** and scan the recovered code for secrets. |
| `graphql_check` | Discover GraphQL endpoints and test whether **introspection** is enabled. |
| `graphql_probe` | **Deep GraphQL** — the classes that pay out even with introspection OFF: **batch abuse** (an array of queries in one request → rate-limit/brute-force amplifier, batched-login credential stuffing), **field-suggestion schema recovery** (a typo'd field → *"Did you mean …?"* leaks real names without introspection), **aliases**, and a nested-traversal **BOLA** lead. Detection-only. |
| `ws_probe` | **WebSocket detection** (the surface most scanners skip): RFC 6455 handshake by hand (stdlib) to confirm the endpoint, then the flagship **Cross-Site WebSocket Hijacking (CSWSH)** check — a foreign `Origin` still upgrading means Origin isn't validated, so a cookie-authed socket is hijackable. Reports a lead; `probe_message` (opt-in) sends one benign frame to check echo/reflection. |
| `discover_parameters` | Brute a wordlist of param names → flag hidden params the app reacts to: `reflected` (XSS/SSRF/injection entry point) or behavioural `status`/`length` change. |
| `waf_detect` | Fingerprint WAF/CDN (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, F5, …). |
| `takeover_check` | Subdomain-takeover detection over a 40+ provider fingerprint DB (S3, GH Pages, Heroku, Azure, …). |
| `open_redirect` | Inject a canary into common redirect params (url, next, returnTo, …) — Location / meta / JS. |
| `trace_redirects` | Follow a URL's **redirect chain** hop by hop and flag offsite / `https→http` downgrade / leaves-scope / loop / meta-refresh / JS redirect (OAuth `redirect_uri`, SSRF-via-redirect). |
| `vcs_exposure` | Confirm exposed `.git`/`.svn`/`.env`/`.DS_Store` by content signature; extract git remote + commit log. |
| `git_forensics` | **Git-history forensics** on an exposed `.git` (the deep follow-up to `vcs_exposure`) — reconstructs history from what the server serves (read-only) and mines it: `.git/config` remote **credentials**, `.git/logs/HEAD` reflog (SHAs + author emails + messages), `.git/index` **tracked file list** (flags `.env`/`id_rsa`/`*.sql`), and a bounded **loose-object walk** (commit→tree→blob) running the secret scanner over history. Packed history is detected + flagged for git-dumper/Strix. Secrets redacted. |
| `screenshot` | Render a page to PNG via Playwright+Chromium **when installed** (else a graceful note). |
| `browser_open` | Drive a **headless browser**: render a JS-heavy SPA and return the post-JS text/HTML, the **console log**, the **network requests** the page made, and page errors — endpoint/secret discovery a raw fetch can't see. Uses `auth_set`. |
| `browser_eval` | Run JavaScript in the page (the **browser console**) and return the result + console log — inspect the live DOM, read `window`/JS state, extract SPA-rendered data. |
| `browser_interact` | Drive a real **user flow** — click / fill / type / submit / wait / eval steps — and return the resulting page state plus **cookies & localStorage** (login, multi-step forms, SPA navigation). |
| `analyze_binary` | Download a compiled artifact (.dll/.exe/.jar/.so) → filetype (incl. .NET), strings (ASCII+UTF-16), secrets, URLs, conn-strings; optional `ilspycmd` decompile. |
| `analyze_config` | Parse a config file (.env/INI/JSON/YAML/.properties/XML/PHP) → **every setting** by category + flags (secrets, DEBUG, TLS-off, wildcard CORS, weak creds, conn-strings). |
| `favicon_hash` | Shodan-style favicon mmh3 hash + `http.favicon.hash:` pivot query (find siblings / origin behind CDN). |
| `tls_fingerprint` | Supported TLS versions (flags weak 1.0/1.1), cipher per version, ALPN / HTTP-2. |
| `jarm_fingerprint` | JARM active TLS fingerprint (62-char; verified byte-for-byte vs Salesforce) for infra/C2 pivoting. |
| `origin_discovery` | Find the real origin IP behind a CDN/WAF via cert SANs, non-proxied subdomains and MX. |
| `behavior_probe` | Behavioural profile: soft/custom-404, stack-trace disclosure, Host / X-Forwarded-Host reflection, methods, timing. |

### 🟠 Active — intrusive (gated by `MOONMCP_ALLOW_INTRUSIVE`)
| Tool | Purpose |
| --- | --- |
| `port_scan` | Unprivileged TCP connect-scan (`top` set or a custom range), optional banners. |
| `content_discovery` | Probe for sensitive paths (admin, `.git`, `.env`, backups, API docs, …). |
| `http_methods` | Enumerate allowed methods + probe risky ones (TRACE/PUT/DELETE/PATCH → XST / write-enabled). |
| `waf_efficacy` | Test which attack categories the WAF blocks (benign canaries) + whether simple transforms bypass it. |
| `desync_probe` | Detection-only request-smuggling indicators (CL+TE / obfuscated TE); complete-message probes, never poisons a connection. |
| `desync_modern_probe` | Modern desync (2025 class): 0.CL / TE.0 / `Expect: 100-continue` / chunk-extension via response-timeout deltas on raw closed sockets (CVE-2025-32094 / CVE-2025-55315). Detection-only. |
| `cache_deception_probe` | Web-cache **deception**: primes a path-confusion variant (`/x.css`, `;x.css`, `%2f`) of the private page and re-reads it cookieless → a cached authed body under an attacker-readable key. |
| `ssrf_metadata_probe` | Response-based SSRF → **cloud-metadata credential theft** (AWS/GCP/Azure/Alibaba/Yandex/Oracle/DO): injects each provider's IMDS URL and scans for its credential signature. |
| `logic_probe` | Business-logic abuse: mass-assignment (privileged fields echoed back) + value/quantity tampering. |
| `value_probe` | Money-aware value manipulation (negative/overflow/precision/>100 % discount, currency swap, single-use-coupon reuse). |
| `race_probe` | Single-packet **race condition** (HTTP/1.1 last-byte sync) → non-atomic per-user limits (coupon/withdrawal double-spend). |
| `workflow_probe` | **Step-skipping** on a multi-step flow — fetch each step cold (without its prerequisites) → order confirmed without payment, account active without verification. |
| `jwt_jku_probe` | JWT `jku`/`x5u` **key-injection SSRF** — re-issues the token with a `jku` pointing at an OAST canary; a callback = the server fetched attacker key material (CVE-2018-0114). |
| `vuln_scan` | Run a `nuclei` template scan (requires nuclei installed). |

### 🗄️ Databases, data stores & advanced injection
Detection-only DB attack-surface coverage. Every probe is a read-only fetch, a benign
two-request differential, an error-string match, or an OAST callback — weaponization
(dump, `--os-shell`, `CONFIG SET`/`SLAVEOF`/`MODULE LOAD`, gadget/JNDI chains) is
delegated to **sqlmap** / **Strix** under human confirmation.
| Tool | Purpose |
| --- | --- |
| `db_exposure` | **Unauthenticated datastore sweep** — speaks each store's minimal read-only handshake: Redis `PING`/`INFO`, memcached `version`, a hand-built MongoDB `listDatabases` OP_MSG, and HTTP reads for Elasticsearch/OpenSearch, CouchDB, InfluxDB, Hadoop YARN, TiDB. Intrusive. |
| `nosqli_probe` | **NoSQL (MongoDB) operator injection** — sends an *object* where a string is expected (`$ne`/`$gt`/`$nin`, bracket **and** JSON forms) + a `$where` boolean oracle; flags a reproducible auth/record flip. Intrusive. |
| `graphql_nosqli` | **GraphQL → Mongo/Mongoose operator injection** — after `graphql_check`, sends an operator object as a GraphQL **variable** vs a string baseline; flags a resolver data/auth flip or a Mongoose `CastError`. Intrusive. |
| `second_order_sqli_probe` | **Stored / second-order SQLi** — seeds a tagged payload at a *write* endpoint, drives the *read* endpoints, correlates the SQL error/differential by tag (the sink is a different endpoint — invisible to any stateless matcher). Intrusive. |
| `orm_leak_probe` | **ORM leak** (Django/Prisma/Rails) — injects a relational lookup (`<field>__startswith`) to filter by a hidden field (`password`, `reset_token`) via a true/false differential. Intrusive. |
| `parser_diff_probe` | **HTTP parser-differential / WAF-bypass multiplier** — pairs a canonical request with quirk-twins (UTF-7 / overlong-UTF-8 **decode**, duplicate JSON keys / comments / BOM / bare-LF multipart **tolerance**) to find where the app and a fronting WAF parse differently. Intrusive. |
| `fastjson_oast_probe` | **Java fastjson/Jackson autoType** — POSTs a benign `@type` OAST canary (`Inet4Address`/`URL`); a DNS/HTTP callback = the endpoint deserializes attacker-controlled `@type`. Intrusive, OAST. |
| `ssrf_protocol_probe` | **SSRF → internal datastore** — scheme-deref OAST canaries (`gopher`/`dict`/`ftp`) + an internal-port reachability differential (`http://127.0.0.1:<db_port>/`). Intrusive. |
| `stack_probe` | Fingerprint + unauth reads for **ClickHouse**, **Druid** (session-leak via `/druid/websession.json`), **vector stores** (Chroma/Weaviate/Qdrant), Nacos, ThinkPHP, Shiro, 1C-Bitrix. Intrusive. |
| `cspp_probe` | **Client-side prototype pollution** — loads `__proto__`/`constructor` URL paths (query + hash) in MoonMCP's **own** headless browser and reads `Object.prototype[marker]` back. Safe by design — the pollution lands in our throwaway Chromium, never the target. Light active. |
| `firebase_exposure` | **Open Firebase RTDB** — harvests the app's own `databaseURL`/`projectId` from its JS, then one shallow unauth read. Light active. |
| `supabase_exposure` | **Supabase RLS-off** — harvests the public `anon` key, enumerates the PostgREST schema, then a per-table `limit=1` read with that key. Light active. |
| `debug_exposure` | DB/admin **panels** by path→signature: Adminer (+ CVE-2021-21311 rogue-MySQL note), phpMyAdmin, Mongo-Express, pgAdmin, RedisInsight, ClickHouse `/play`. Light active. |

### 🧰 Interception (Burp-style, native — no external proxy)
| Tool | Purpose |
| --- | --- |
| `http_repeater` | **Repeater** — send one fully-controlled request (structured **or** a `raw` Burp-style HTTP request) to an in-scope target; full response + quick passive scan; logged for replay. |
| `intruder` | **Intruder** — a request `template` with a `§` marker + payload list, fired and **diffed** (status / length / reflection) vs a baseline → injection/IDOR entry points. Intrusive. |
| `passive_scan` | One benign GET → all passive analysers at once (header grade + issues, tech fingerprint, redacted secret hits). |
| `confirm_finding` | **Prove a lead before reporting it:** baseline vs test request → weighs **reflection**, status/length/timing diff, **injection signatures**, and an **out-of-band callback** (OAST) into a verdict (`confirmed` / `likely` / `inconclusive` / `unconfirmed`). Optionally records a confirmed hit. |
| `ssti_probe` | **SSTI** detector — arithmetic markers per engine (Jinja2/Twig, Freemarker, ERB, Smarty, Velocity, Razor); reports which engine *evaluated* the expression. Intrusive. |
| `sqli_probe` | **SQLi** detector — error signatures + a reproducible boolean pair, plus opt-in lanes: `context` (ORDER BY / LIMIT), `oob` (per-DBMS OAST), `time_based` (monotonic-guarded), `waf_bypass` (JSON-operator), `multibyte` (Shift-JIS/EUC-KR/GBK), and header/cookie placement. Reports the DBMS; no data extraction (→ sqlmap). Intrusive. |
| `cmdi_probe` | **Blind OS command injection** detector — a small, non-combinatorial set of shell separators (`;` `\|` `&&` `&` backtick `$()`), each carrying only a side-channel payload (`sleep N`, confirmed by the same monotonic-timing check as `sqli_probe`'s `time_based` lane; or an **OAST** callback). Never sends an output-eliciting payload (`id`, `cat /etc/passwd`, `dir`) — command output is never displayed (→ Strix). Intrusive. |
| `lfi_probe` | **Path traversal / LFI** content-disclosure — depth-escalating `../` (x1/3/6/8), null-byte, double-URL-encoded, and Windows-style variants, confirmed by a genuine **file-content signature** (`root:x:0:0:`, win.ini markers) in the response — proof the traversal reached the filesystem, not just that a WAF let the payload shape through. Reads only universally-present, non-sensitive files. Intrusive. |
| `ssrf_probe` | **Blind SSRF** detector — plants an OAST canary in a param and checks for a callback (start `oast_selfhost` first). Intrusive. |
| `cache_probe` | **Web cache poisoning** detector — unkeyed-header reflection (`X-Forwarded-Host`, …) × cacheability. Intrusive. |
| `http_history` | Review / fetch / clear the session's request-response **history** (what repeater/intruder/passive_scan sent). |

### 🏗️ Behavioural infrastructure (infer the infra from response *variance*)
| Tool | Purpose |
| --- | --- |
| `backend_probe` | **Infer the backend fleet behind a load balancer:** clusters N responses by their discriminators (Server, Via, backend-id headers, cookie names) → distinct backends, **patch drift** (nodes on different Server versions — one may be individually vulnerable) and **clock skew**. |
| `dns_behavior` | **DNS/zone behaviour:** wildcard-DNS detection (so subdomain enum isn't fooled), DNS load-balancing (rotating A records), IPv6, and the CNAME target (dangling → takeover surface). |
| `vhost_probe` | **Host-header routing:** does the edge validate the Host or serve the same app for any host (cache/reset poisoning surface)? Is a bogus host **reflected** (host-header injection) directly or via `X-Forwarded-Host`? |
| `ratelimit_probe` | **Rate-limit behaviour:** finds the throttle threshold/window, `Retry-After`, and whether spoofing `X-Forwarded-For` **resets** the limit (per-IP bypass). Intrusive. |
| `tls_behavior` | **TLS routing behaviour:** real-host vs **bogus-SNI** cert diff (→ SNI routing / shared hosting / default-cert origin hint), supported versions (flags weak TLS 1.0/1.1), cipher, HTTP/2. |
| `edge_map` | **Edge topology:** which CDN/WAF/cache vendors front the origin (Cloudflare/CloudFront/Fastly/Akamai/Sucuri/Imperva…), the `Via` proxy chain, cache layer — are you hitting the edge or the origin? |
| `http_behavior` | **Raw HTTP/1.x fingerprint** (intrusive): reactions to HTTP/1.0, an unknown method, an oversized header, and **bare-LF** line endings → lenient parsing / proxy-origin mismatch (desync surface). Detection-only. |

### 🔗 Orchestration & reporting
| Tool | Purpose |
| --- | --- |
| `probe_batch` | Probe a **list** of hosts/URLs in parallel (liveness, status, title, tech) — the enum→probe step; feed it `enumerate_subdomains`. Scope-gated + rate-limited. |
| `recon_target` | One-shot passive+light sweep (subdomains → DNS → TLS → HTTP → headers → fingerprint → email security). |
| `report` | Full safe sweep → a severity-ranked **Markdown** report (surface, posture grades, findings). |
| `add_finding` / `list_findings` / `clear_findings` | Record / read / clear findings in the session store (also on the `findings://` resource). |
| `triage_findings` | **Dedupe + prioritise** findings before reporting: collapse exact duplicates, rank by severity × frequency, and surface **systemic** issues (same finding across many targets). Dry-run or `apply=true`. |
| `cvss_score` | Compute a **CVSS 3.1 base score** + severity band from a vector or individual metrics — so a confirmed finding carries a defensible standard severity. Offline. |
| `export_findings` | Export findings as **SARIF 2.1.0** (GitHub code-scanning / DAST pipelines) or JSON. |
| `export_obsidian` | "Graphify" the session into an **Obsidian vault** — linked notes (asset ↔ finding, vuln ↔ root cause) + tags + an Obsidian **Canvas** graph. Open the folder and use the graph view. |
| `surface_diff` / `surface_snapshots` | Track how the attack surface **changes over time** — baseline a set (subdomains/endpoints/…) and surface only what's **new** since last run (persists via `MOONMCP_STATE_DIR`). |

### 🧠 Shared memory hub (persistent, cross-agent)
| Tool | Purpose |
| --- | --- |
| `memory_add` | Store an item in a **shared, persistent** knowledge store (SQLite; persists via `MOONMCP_STATE_DIR`) so multiple agents/sessions build on each other's work. Every item is **trust-tagged** — `untrusted` (scraped/observed content — a prompt-injection vector) vs `curated` (a vetted conclusion). |
| `memory_search` | Full-text search (bm25 via SQLite **FTS5**, LIKE fallback) over the hub; filter by `kind` / `target` / `trust` (`trust=curated` returns only vetted knowledge). Also on `memory://recent`. |
| `memory_get` / `memory_stats` | Fetch one item; summarise the hub (counts by kind/trust). `add_finding` auto-mirrors findings into the hub as `curated`. |
| `memory_brief` | **What do we know about TARGET?** — one-shot rollup for orienting before/resuming work: graph entities by kind, confirmed findings, open leads, applicable lessons, counts. Call it first on a target. |
| `memory_graph` / `memory_link` | Read / build the **knowledge graph** — typed entities (host / endpoint / param / technology / service / cve / …) and typed relations (`affects` / `on` / `uses` / `caused_by` / …) between them and findings. `add_finding` auto-links a finding to its host + endpoint, turning flat findings into a queryable structure. |
| `memory_lesson` | The **learning loop** — record (`action=add`) and recall (`action=recall`) durable, cross-target **lessons** (tradecraft, false-positive traps, tool quirks) so mistakes and wins carry forward between sessions and agents. |

### 🛠️ External tools
| Tool | Purpose |
| --- | --- |
| `external_tools` | List known security CLIs (36, categorised) and whether each is installed + its native fallback. |
| `run_scanner` | Run an installed CLI (`subfinder`, `httpx`, `nuclei`, `nmap`, `ffuf`, …); JSONL auto-parsed; intrusive scanners gated by `MOONMCP_ALLOW_INTRUSIVE`. |

### 📚 Knowledge bases
Referenced catalogs built into the server (offline, searchable as tools + MCP resources) — descriptions, detection guidance and links to public research, **not** weaponized exploit code:
- **Injections** — **29 classes** (255 detection payloads · 318 response signatures). [`docs/INJECTIONS.md`](docs/INJECTIONS.md)
- **Exploitation techniques & notable PoCs** — **115 techniques** across **14 categories**, from assembler-level memory corruption to the highest-level web / supply-chain. [`docs/TECHNIQUES.md`](docs/TECHNIQUES.md)
- **Privilege escalation** — **129 techniques** (Linux · Windows · container · cloud · Active Directory · macOS) + **68 tools**. [`docs/PRIVESC.md`](docs/PRIVESC.md)
- **Server-side vulnerabilities** — **44 classes** (popular *and* obscure), each mapped to its **root cause** and the concrete point where apps break, + **29 tools**. [`docs/SERVER_SIDE_VULNS.md`](docs/SERVER_SIDE_VULNS.md)
- **Root-cause taxonomy** — the **13 fundamental causes** from which nearly all server-side bugs spring, each with its systemic fix. *Where the core of all problems is.* [`docs/ROOT_CAUSES.md`](docs/ROOT_CAUSES.md)
- **WAF reference** — **24 entries**: how WAFs work, vendor **fingerprints**, and conceptual/defensive **bypass** classes. [`docs/WAF.md`](docs/WAF.md)

| Tool | Purpose |
| --- | --- |
| `injection_info` / `injection_search` | Look up / search one of 29 injection classes (sqli, nosqli, xss, ssti, cmdi, xxe, xpath, ldapi, ssrf, crlf, prototype-pollution, prompt-injection, …): detection payloads, root causes, per-engine signatures. |
| `match_injection_signatures` | Scan a response body for known injection error signatures → which class + technology (e.g. `ORA-01756` → Oracle SQLi). |
| `technique_info` / `technique_search` | 115 exploitation techniques & landmark public PoCs across all languages/levels — descriptions + links, not exploit code. |
| `privesc_info` / `privesc_search` | 129 privilege-escalation techniques across Linux/Windows/container/cloud/AD/macOS: enumeration commands, detection indicators, mitigations, references. |
| `privesc_tools` | Catalog of 68 privesc tools (LinPEAS/WinPEAS, GTFOBins, LOLBAS, PowerUp, Seatbelt, pspy, potato family, BloodHound, Impacket, …). |
| `match_privesc` | Scan pasted enumeration output (`sudo -l`, `id`, `getcap -r /`, `whoami /priv`, `systeminfo`) → which escalation vectors it indicates. |
| `vuln_info` / `vuln_search` / `vuln_tools` | 44 server-side vuln classes (popular + obscure) with root cause, `where_it_breaks`, detection, WAF notes and real-world incidents; + a 29-tool discovery catalog. |
| `rootcause_info` | The root-cause taxonomy — the ~13 fundamental causes underneath all these bugs, each with why it recurs, the systemic fix, and the catalog vulns that derive from it. |
| `waf_info` / `identify_waf` | WAF KB (how they work · fingerprints · bypass concepts); `identify_waf` names the vendor from a raw HTTP response (CF-RAY, `__cfduid`, `x-akamai`, `incap_ses`, BigIP, …). |

**Resources:** `moonmcp://scope`, `moonmcp://capabilities`, `findings://current`, `injections://all`, `techniques://all`, `privesc://all`, `vulns://all`, `rootcauses://all`, `waf://all`, `audit://recent`

**Operator prompts** ([`docs/SYSTEM_PROMPTS.md`](docs/SYSTEM_PROMPTS.md)) — system prompts that make an agent using MoonMCP plan, pick the right tool, verify before it reports, minimise false positives and stay strictly in scope. Synthesised from real pentest-agent prompts (CAI, PentestGPT, XBOW, HexStrike), agent prompt-engineering (ReAct, Plan-and-Execute, Chain-of-Verification, Reflexion) and bug-bounty methodology (TBHM, OWASP WSTG, PortSwigger, HackerOne/Bugcrowd):
- `bug_bounty_operator` — master engagement prompt (rules of engagement + OODA-style loop + tool map).
- `deep_recon` — exhaustive 5-phase attack-surface mapping.
- `injection_hunt` — KB-backed injection hunt with benign canaries + signature confirmation.
- `technique_advisor` — referenced technique guidance for an observed tech/CVE.
- `triage_and_report` — verify, dedupe, severity-rate and write accepted-quality reports.
- `safe_recon` — conservative, passive-first, scope-strict default.
- `privesc_hunt` — KB-backed privilege-escalation triage from an authorised foothold (enumerate → `match_privesc` → verify).
- `recon_methodology` — the original quick-start recon playbook.

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

### Use it from a shell-based agent (no MCP client needed)

Any agent with a shell (or a CI step) can drive MoonMCP without an MCP client:

```bash
moonmcp tools                                              # list exposed tools
moonmcp call fingerprint   --arg target=https://example.com
moonmcp call injection_info --json '{"injection_class":"ssti"}'
```

Each call prints JSON; scope-gated tools still enforce `MOONMCP_SCOPE`. Expose a
**curated slice** with a profile — `MOONMCP_PROFILE=strix` (knowledge + memory +
recon + findings; hides the heavy scanners/proxy), or `passive` / `knowledge` /
`recon`, or fine-grained `MOONMCP_EXPOSE_TOOLS` / `MOONMCP_HIDE_TOOLS`. This is how
MoonMCP plugs into a tool like **Strix** as a shared brain/memory/guard
(see [`docs/STRIX_INTEGRATION.md`](docs/STRIX_INTEGRATION.md)).

### Claude Code skill

A packaged **skill** ships in [`.claude/skills/moonmcp/`](.claude/skills/moonmcp/SKILL.md)
that teaches an agent the MoonMCP workflow, the rules of engagement, and the tool
map. Copy that folder into your `~/.claude/skills/` (or a project's `.claude/skills/`)
and the agent will orient itself with `server_status` + `tool_catalog` and drive
the tools in the right order — scope/program first, passive → light → intrusive
(with consent) → report.

A second skill, `strix-orchestration`, teaches an agent to drive MoonMCP
(fast, scope-first **detection**) together with [Strix](https://github.com/usestrix/strix)
(autonomous **validation** with working PoCs) as two MCP tools of the *same* agent
— MoonMCP finds, Strix confirms. See [`docs/STRIX_INTEGRATION.md`](docs/STRIX_INTEGRATION.md)
and the scope-gated reference wrapper in [`examples/strix_mcp/`](examples/strix_mcp/server.py).

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
| `MOONMCP_SCREENSHOT_DIR` | *(temp dir)* | Where the `screenshot` tool writes PNGs. |
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

### Program profiles (one header per program)

Bug-bounty programs each want their own identifying header on your traffic so
their WAF/SOC recognises authorised testing. A **program profile** bundles that
with the program's scope:

```
program_add(name="acme", scope="*.acme.com, api.acme.io",
            exclude="blog.acme.com",
            header="X-HackerOne-Research: yourhandle",
            user_agent="acme-recon/1.0")     # activates by default
program_use(name="acme")                     # switch engagements later
```

Activating a program swaps in **its** scope and auto-attaches its header +
User-Agent to every **in-scope** request (through the same merge path as
`auth_set`, so it never leaks to out-of-scope hosts). Profiles persist to
`MOONMCP_STATE_DIR`, so a restart resumes the same engagement. Engagement
credentials from `auth_set` still layer on top and win on a key collision.

---

## How a tool call is processed

Every packet-sending tool wears **one decorator — `@active_tool`** — that is the
single place scope lives, so behaviour is uniform and safe:

1. **Normalise** the target — a URL, `host:port`, bracketed IPv6 or bare host is
   reduced to a canonical host.
2. **Classify & gate** — the tool declares its class via the decorator:
   *passive OSINT* (third-party datasets, e.g. `ip_intel`, `cve_search`) runs
   without touching the target; *light active* (`@active_tool()`, e.g.
   `http_probe`, `favicon_hash`) and *intrusive* (`@active_tool(intrusive=True)`,
   e.g. `port_scan`, `waf_efficacy`) route through `_require_scope`, which fails
   closed if the host isn't in scope, is a blocked private IP, or — for intrusive
   tools — `MOONMCP_ALLOW_INTRUSIVE` is off. A CI guard test asserts every
   packet-sending tool carries the gate, so an un-gated capability can't ship.
3. **Rate-limit** — all outbound traffic passes one shared token-bucket +
   concurrency `Governor`, so a fan-out never exceeds `MOONMCP_RATE_LIMIT`.
4. **Execute** on the async stdlib layer (blocking calls wrapped in
   `asyncio.to_thread`), preferring an installed CLI when present and detected.
5. **Structure the result** — dataclasses are converted to clean JSON; the HTTP
   client caps body size and re-checks redirects against scope.
6. **Contain failures** — the `@active_tool` gate (and the `@safe_tool` wrapper it
   applies) turns scope/validation errors into structured `{"error": …}` objects
   instead of exceptions, so one bad input never crashes the session.

---

## Augmenting with external CLIs

MoonMCP has native, stdlib implementations for the whole recon workflow, but it
gets sharper when best-in-class tools are on `PATH` — on **Kali** most already
are. It auto-detects and can run **36 tools**, grouped by category:

| Category | Tools |
| --- | --- |
| subdomain | `subfinder`, `amass`, `assetfinder`, `subjack` |
| dns | `dnsx`, `dnsrecon`, `dnsenum`, `asnmap` |
| http | `httpx`, `whatweb`, `wafw00f`, `gowitness` |
| crawl / url | `katana`, `hakrawler`, `gospider`, `gau`, `waybackurls` |
| content 🔸 | `ffuf`, `feroxbuster`, `gobuster`, `dirb`, `arjun` |
| port 🔸 | `naabu`, `nmap`, `masscan` |
| vuln / cms 🔸 | `nuclei`, `nikto`, `wpscan`, `sqlmap`, `dalfox` |
| tls | `sslscan`, `sslyze`, `testssl.sh`, `tlsx` |
| decompile | `ilspycmd`, `monodis` |

🔸 = **intrusive** — `run_scanner` gates these behind `MOONMCP_ALLOW_INTRUSIVE`
(on top of the scope check), exactly like the native intrusive tools. If a tool
is missing, MoonMCP returns a clear note and the **native fallback** to use
instead — nothing errors out. Call `external_tools` for the live, categorised
inventory (installed + install hints).

> Note: the ProjectDiscovery `httpx` binary and the Python `httpx` library share a
> name. MoonMCP detects and ignores the Python shim so it won't be mistaken for the
> scanner.

---

## Architecture

```
moonmcp/
├── server.py        # FastMCP server: 158 tools, 11 resources, 9 prompts (@active_tool = the one scope gate)
├── catalog.py       # self-describing tool map (tool_catalog): families + gate flags + workflow
├── confirm.py       # finding-confirmation scoring (differential + OAST + signatures)
├── cvss.py          # CVSS 3.1 base-score calculator
├── web/probes.py    # active detectors: SSTI / SQLi / SSRF / cache poisoning
├── recon/infra.py   # behavioural infra analysers (backend fleet, DNS, vhost, rate-limit)
├── intel/oast_server.py  # built-in OAST callback catcher (self-host)
├── memory.py        # shared persistent memory hub (SQLite + FTS5, trust/provenance tags)
├── intercept.py     # Burp-style repeater / intruder / passive scan + request-response history
├── programs.py      # bug-bounty engagement profiles (per-program scope + header + UA)
├── prompts.py       # operator system prompts (see docs/SYSTEM_PROMPTS.md)
├── scope.py         # ScopeManager — the authorization guardrail
├── config.py        # env-driven Settings
├── context.py       # shared Settings + Scope + rate Governor + HttpClient + Programs
├── net/             # stdlib networking (async via asyncio.to_thread)
│   ├── http.py      #   urllib-based HTTP client w/ redirect tracing + rate limit
│   ├── dns.py       #   getaddrinfo + DNS-over-HTTPS (+ optional dnspython)
│   ├── tls.py       #   ssl-based cert inspection + TLS version/cipher/ALPN profile
│   ├── jarm.py      #   JARM active TLS fingerprint (verified vs salesforce/jarm)
│   ├── ports.py     #   asyncio TCP connect-scan
│   └── ratelimit.py #   token-bucket + concurrency governor
├── recon/           # subdomains, fingerprint, headers, wayback, content, crawl, secrets, binary, favicon, origin, config_audit
├── web/             # cors, graphql, waf(+efficacy), jwt, methods, takeover, redirect, exposure, screenshot, behavior
├── intel/           # cve (NVD), shodan, email (SPF/DMARC/DKIM/CAA), asn (ASN/cloud/reverse-IP), search (multi-engine), reader (OSINT page reader)
├── reporting.py     # pure Markdown report renderer
├── findings.py      # session findings store (findings:// resource)
├── knowledge/       # injection KB + techniques/PoC catalog (injections:// / techniques:// resources)
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
pytest -q          # 190+ tests: scope logic, the @active_tool gate, program profiles, parsers, web-app checks, local-server integration
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
