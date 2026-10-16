# 🌙 MoonMCP

MoonMCP is an MCP server for authorised security research and bug-bounty reconnaissance. It gives MCP clients a scope-aware set of tools for OSINT, web and infrastructure reconnaissance, vulnerability detection, finding management, and security research workflows.

The project is **stdlib-first**: its core reconnaissance features work without a large external toolchain. When compatible security CLIs are installed, MoonMCP can use them as optional extensions.

> **Authorised testing only.** Use MoonMCP only on systems you own or have explicit permission to test. Always follow the target program's scope, rules and applicable law.

## What it provides

- **Scope controls** — allow/exclude domains, hosts, IPs and CIDRs; active tools fail closed outside the configured scope.
- **Reconnaissance** — DNS, HTTP/TLS inspection, fingerprinting, subdomain discovery, historical URLs, crawling, JavaScript analysis and OSINT.
- **Web security checks** — structured checks for common access-control, configuration, injection, WebSocket, GraphQL, OAuth, cache and server-side issues.
- **Finding workflow** — confirmation helpers, CVSS scoring, deduplication, reporting, SARIF/JSON export and surface snapshots.
- **Persistent research context** — optional SQLite-backed memory and a small knowledge graph for findings, assets and research notes.
- **Resumable assessments** — persistent runs, role-based tasks, dependency ordering, coverage tracking, usage budgets and immutable evidence artifacts.
- **Observations and hypotheses** — persistent flags with evidence, source groups, role/time context, links and counterevidence; reviewed hypotheses remain distinct from confirmed findings.
- **Optional CLI integration** — can detect and use tools such as `nuclei`, `httpx`, `subfinder`, `nmap` and others when they are available.
- **Safety controls** — scope enforcement, request rate/concurrency limits, private-address protection, audit logging and a separate gate for intrusive tools.

Use `tool_catalog` from an MCP client, or `moonmcp tools` from the shell, for the current tool list. This avoids relying on README counts as the project evolves.

## Quick start

Requires **Python 3.10+**.

```bash
# uv
uv tool install --from . moonmcp

# or pip
pip install .

# verify the installation
moonmcp --check
```

### MCP client configuration

```json
{
  "mcpServers": {
    "moonmcp": {
      "command": "moonmcp",
      "env": {
        "MOONMCP_SCOPE": "*.example.com,203.0.113.0/24",
        "MOONMCP_ALLOW_INTRUSIVE": "0"
      }
    }
  }
}
```

A fuller example is available in [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json).

MoonMCP can also be used directly from a shell:

```bash
moonmcp tools
moonmcp call fingerprint --arg target=https://example.com
moonmcp call injection_info --json '{"injection_class":"ssti"}'
```

Scope checks still apply to shell calls.

### Resumable assessment runs

Set `MOONMCP_STATE_DIR` to retain runs, findings and evidence across restarts. Use
`run_start` with an authorised target, `run_brief` to resume context, and `run_claim`
with a heartbeat for coordinated work. Discover a tool with `tool_search`, inspect
its schema and request accounting through `tool_describe`, then use `run_execute`
for supported local/HTTP tools. It records calls and HTTP sends against the run
budget; direct typed calls do not automatically join that budget.

Large results are preserved in ordered artifact chunks with SHA-256 manifests;
summary mode shortens the preview. Interrupted outcomes need evidence-backed
reconciliation through `run_recover`/`run_reconcile` before explicit task retry.
`run_finish` checks unfinished work and preserves coverage limitations. See the
[agent workflow guide](docs/AGENT_WORKFLOW.md) for exact recovery rules and the
flag → hypothesis → verification workflow.

`MOONMCP_COMPACT=1` advertises a smaller facade when the selected profile includes
both `run_start` and `run_execute`. Profiles without that pair, such as `knowledge`,
keep their direct tools. Compact does not bypass profile permissions or make
unmetered browser, CLI or raw-protocol tools executable through the run facade.

Operator skills in `.claude/skills/assessment-planning`,
`.claude/skills/systematic-validation`, and `.claude/skills/run-coordination`
describe planning, evidence validation and coordination through these MCP tools.

## Scope and safety

Scope is the main authorization boundary for active testing.

| Entry | Meaning |
| --- | --- |
| `example.com` | apex and subdomains |
| `*.example.com` | subdomains only |
| `api.example.com` | that host and deeper labels |
| `203.0.113.10` | one IP |
| `203.0.113.0/24` | CIDR range |

Exclusions override inclusions. With scope enforcement enabled, active tools refuse targets that are not authorised. Private, loopback, link-local and reserved addresses are blocked by default; this can be changed for explicitly authorised internal testing.

Intrusive capabilities have a separate `MOONMCP_ALLOW_INTRUSIVE` switch. Outbound requests also share rate and concurrency controls.

## Configuration

Common settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `MOONMCP_SCOPE` | empty | authorised domains, hosts, IPs or CIDRs |
| `MOONMCP_SCOPE_EXCLUDE` | empty | explicit exclusions |
| `MOONMCP_ENFORCE_SCOPE` | `1` | enforce active-tool scope checks |
| `MOONMCP_BLOCK_PRIVATE` | `1` | block private/reserved destinations |
| `MOONMCP_ALLOW_INTRUSIVE` | `0` | enable separately gated intrusive tools |
| `MOONMCP_RATE_LIMIT` | `10` | outbound requests per second |
| `MOONMCP_MAX_CONCURRENCY` | `20` | concurrent outbound connections |
| `MOONMCP_TIMEOUT` | `10` | default request timeout |
| `MOONMCP_ALLOW_EXTERNAL_TOOLS` | `1` | permit installed CLI integrations |
| `MOONMCP_STATE_DIR` | `~/.hermes/moonmcp_state` | persistent runs, findings, flags and program/memory state |
| `MOONMCP_COMPACT` | `0` | advertise the run facade when the selected profile supports it |

See the source and documentation for specialised integrations and provider-specific API keys.

## Documentation

Start implementation work with the [consolidated priorities](docs/IMPLEMENTATION_PRIORITIES.md).
They distinguish near-term fixes and the BOLA proof path from conditional research,
link all retained discovery proposals, and credit capabilities that already exist.
Merging a roadmap does not implement its features.

Technical and operating references:

- [Implementation priorities and discovery-plan index](docs/IMPLEMENTATION_PRIORITIES.md)
- [Capability audit and roadmap reconciliation (2026-10-15)](docs/CAPABILITY_AUDIT_2026-10-15.md)
- [Research and design notes](docs/RESEARCH.md)
- [Autonomy roadmap](docs/AUTONOMY_ROADMAP.md)
- [Agent navigation and optimization plan](docs/AGENT_NAVIGATION_PLAN.md)
- [Agent workflow: tools, flags, hypotheses and recovery](docs/AGENT_WORKFLOW.md)
- [Tool registry and registration architecture](docs/TOOL_ARCHITECTURE.md)
- [Execution results and errors: versioned contract](docs/TOOL_OUTCOMES.md)
- [Implemented private-object verification, agent workflow and remaining limits](docs/VERIFIED_AUTHORIZATION.md)
- [Research into comparable flag and hypothesis systems](docs/FLAG_SYSTEM_RESEARCH.md)
- [Strix integration](docs/STRIX_INTEGRATION.md)
- [System prompts](docs/SYSTEM_PROMPTS.md)
- [Injection reference](docs/INJECTIONS.md)
- [Security techniques](docs/TECHNIQUES.md)
- [Privilege escalation reference](docs/PRIVESC.md)
- [Server-side vulnerability reference](docs/SERVER_SIDE_VULNS.md)
- [Root-cause reference](docs/ROOT_CAUSES.md)
- [WAF reference](docs/WAF.md)

## Development

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev,enhanced]"
pytest -q
ruff check .
```

## Design notes

MoonMCP keeps active target access behind shared scope controls rather than leaving authorization decisions to individual workflows. Core features prefer Python implementations, while external security tools remain optional integrations.

The project includes passive and active capabilities. Detection results should be treated as leads until they are independently verified.

## License

MIT — see [LICENSE](LICENSE).
