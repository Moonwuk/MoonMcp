"""MoonMCP MCP server — tool definitions.

The docstring of each ``@mcp.tool`` becomes the description the model sees, so
they are written to guide correct, safe usage.

Tool families
-------------
* **meta / scope**     — inspect capabilities, manage the authorization scope.
* **passive OSINT**    — never touch the target: subdomains, wayback, CVE, host intel.
* **active (light)**   — benign requests to an in-scope target: DNS, HTTP, TLS,
  headers, fingerprint, well-known files.
* **active (intrusive)** — scanning that must be explicitly enabled: port scan,
  content discovery.
* **orchestration**    — ``recon_target`` chains the safe tools into one report.
* **external**         — detect and run installed CLIs (nuclei/httpx/…), with a
  native fallback when they are absent.
"""

from __future__ import annotations

import asyncio
import os
import platform
from typing import Any

from . import __version__
from . import catalog as catalogmod
from . import confirm as confirmmod
from . import prompts as promptmod
from .context import AppContext, to_dict
from .external import cli
from .intel import email as emailmod
from .intel import oast as oastmod
from .intel import oast_server as oastsrvmod
from .knowledge import injections as injmod
from .knowledge import privesc as privescmod
from .knowledge import techniques as techmod
from .knowledge import vulns as vulnsmod
from .knowledge import waf_kb as wafkbmod
from .mcp_core import (
    _collect_oast,
    _connect_pin,
    _require_scope,
    _scope_check,
    _split_host_port,
    active_tool,
    get_context,
    mcp,
    safe_tool,
)
from .net import dns as dnsmod
from .net import ports as portsmod
from .net import tls as tlsmod
from .programs import Program, parse_header
from .recon import content as contentmod
from .recon import datastores as datastoresmod
from .recon import fingerprint as fpmod
from .recon import headers as headersmod
from .recon import sourcemaps as sourcemapsmod
from .recon import subdomains as submod
from .reporting import TOOL_NAME, format_markdown
from .scope import ScopeError, normalize_target
from .tools import authtoken as _authtoken_tools  # noqa: F401 (registers token/JWT/OAuth probes)
from .tools import browser_tools as _browser_tools  # noqa: F401 (registers browser-driven tools)
from .tools import infra as _infra_tools  # noqa: F401 (registers infra tools)
from .tools import injection as _injection_tools  # noqa: F401 (registers injection probes)
from .tools import (
    interception as _interception_tools,  # noqa: F401 (registers repeater/intruder/history)
)
from .tools import knowledge as _knowledge_tools  # noqa: F401 (registers KB tools)
from .tools import memory as _memory_tools  # noqa: F401 (registers memory tools)
from .tools import netfp as _netfp_tools  # noqa: F401 (registers net-fingerprint tools)
from .tools import osint as _osint_tools  # noqa: F401 (registers passive-OSINT tools)
from .tools import recon_light as _recon_light_tools  # noqa: F401 (registers light recon)
from .tools import reporting_tools as _reporting_tools  # noqa: F401 (registers findings/reporting)
from .tools import scanners as _scanner_tools  # noqa: F401 (registers external scanner integration)
from .tools import (
    source_analysis as _source_analysis_tools,  # noqa: F401 (registers source/secret analysis)
)
from .tools import (
    static_analysis as _static_analysis_tools,  # noqa: F401 (registers offline analysis)
)
from .tools import webcheck as _webcheck_tools  # noqa: F401 (registers web-app checks)
from .tools.authtoken import (  # noqa: F401,E501
    deserialize_fingerprint,
    jwt_alg_confusion,
    jwt_analyze,
    jwt_crack,
    jwt_jku_probe,
    oauth_probe,
    oauth_redirect_probe,
)
from .tools.browser_tools import (  # noqa: F401,E501
    browser_eval,
    browser_interact,
    browser_open,
    cspp_probe,
    screenshot,
)
from .tools.infra import (  # noqa: F401,E501
    backend_probe,
    dns_behavior,
    edge_map,
    http_behavior,
    ratelimit_probe,
    tls_behavior,
    vhost_probe,
)
from .tools.injection import (  # noqa: F401,E501
    cache_probe,
    cmdi_probe,
    confirm_finding,
    fastjson_oast_probe,
    graphql_nosqli,
    interp_probe,
    lfi_probe,
    nosqli_probe,
    orm_leak_probe,
    parser_diff_probe,
    saml_xsw_probe,
    sqli_probe,
    ssrf_probe,
    ssrf_protocol_probe,
    ssti_probe,
    xxe_probe,
)
from .tools.interception import (  # noqa: F401,E501
    http_history,
    http_repeater,
    intruder,
    passive_scan,
)
from .tools.knowledge import (  # noqa: F401,E501
    identify_waf,
    injection_info,
    injection_search,
    match_injection_signatures,
    match_privesc,
    privesc_info,
    privesc_search,
    privesc_tools,
    rootcause_info,
    technique_info,
    technique_search,
    vuln_info,
    vuln_search,
    vuln_tools,
    waf_info,
)
from .tools.memory import (  # noqa: F401,E501
    memory_add,
    memory_brief,
    memory_get,
    memory_graph,
    memory_lesson,
    memory_link,
    memory_search,
    memory_stats,
)

# Re-export the knowledge tools so `srv.<tool>` still resolves (tests + callers).
from .tools.netfp import (  # noqa: F401,E501
    behavior_probe,
    favicon_hash,
    jarm_fingerprint,
    origin_discovery,
    tls_fingerprint,
)
from .tools.osint import (  # noqa: F401,E501
    cloud_buckets,
    cve_lookup,
    cve_patch_diff,
    cve_search,
    enumerate_subdomains,
    host_intel,
    ip_intel,
    reverse_ip,
    search_dorks,
    variant_search,
    version_vuln_check,
    wayback_urls,
    web_read,
    web_search,
)
from .tools.recon_light import (  # noqa: F401,E501
    analyze_headers,
    dns_lookup,
    fingerprint,
    http_probe,
    tls_inspect,
    well_known,
)
from .tools.reporting_tools import (  # noqa: F401,E501
    add_finding,
    audit_log,
    clear_findings,
    cvss_score,
    export_findings,
    export_obsidian,
    label_finding,
    list_findings,
    metrics,
    promote_lead,
    surface_diff,
    surface_snapshots,
    triage_findings,
)
from .tools.scanners import (  # noqa: F401,E501
    _host_like_tokens,
    _reject_dangerous_scanner_args,
    external_tools,
    run_scanner,
    scan_coverage,
    vuln_scan,
)
from .tools.source_analysis import (  # noqa: F401,E501
    analyze_js,
    crawl,
    extract_secrets,
    firebase_exposure,
    js_library_scan,
    parse_openapi,
    supabase_exposure,
)
from .tools.static_analysis import (  # noqa: F401,E501
    analyze_binary,
    analyze_config,
    dependency_confusion,
    email_security,
)
from .tools.webcheck import (  # noqa: F401,E501
    access_control_check,
    authz_probe,
    cors_audit,
    discover_parameters,
    git_forensics,
    graphql_check,
    graphql_probe,
    open_redirect,
    takeover_check,
    trace_redirects,
    vcs_exposure,
    waf_detect,
    ws_probe,
)
from .web import authflow as authflowmod
from .web import cache_deception as cachedecmod
from .web import cors as corsmod
from .web import crlf as crlfmod
from .web import debugpanel as debugpanelmod
from .web import desync as desyncmod
from .web import exposure as exposuremod
from .web import inject as injectmod
from .web import logic as logicmod
from .web import methods as methodsmod
from .web import pathnorm as pathnormmod
from .web import secondorder as somod
from .web import singlepacket as spmod
from .web import ssrf_meta as ssrfmetamod
from .web import stacks as stacksmod
from .web import takeover as takeovermod
from .web import value as valuemod
from .web import waf as wafmod
from .web import waf_bypass as wafbypassmod
from .web import workflow as workflowmod

# Scanner-integration helpers/constants moved to moonmcp/tools/scanners.py.


# ---------------------------------------------------------------------------
# meta / scope
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def server_status() -> dict:
    """Report MoonMCP's configuration and capabilities.

    Shows the active scope, whether enforcement/intrusive scanning are enabled,
    which optional enhancers (dnspython) are present, and which external security
    CLIs (nuclei, httpx, subfinder, nmap, ...) were detected on PATH. Call this
    first to understand what the server can do in the current environment.
    """

    ctx = get_context()
    s = ctx.settings
    tools = cli.detect_tools()
    return {
        "name": TOOL_NAME,
        "version": __version__,
        "python": platform.python_version(),
        "scope": ctx.scope.entries(),
        "scope_enforced": s.enforce_scope,
        "tool_profile": os.environ.get("MOONMCP_PROFILE") or "full",
        "tools_exposed": len(mcp._tool_manager.list_tools()),
        "active_program": ctx.programs.active.summary() if ctx.programs.active else None,
        "auth_context": ctx.auth.redacted(),
        "block_private_addresses": s.block_private,
        "intrusive_allowed": s.allow_intrusive,
        "external_tools_allowed": s.allow_external_tools,
        "rate_limit_per_sec": s.rate_limit,
        "max_concurrency": s.max_concurrency,
        "enhancers": {"dnspython": dnsmod.dnspython_available()},
        "external_tools_detected": {k: v["available"] for k, v in tools.items()},
        "osint_keys": {
            "shodan": bool(s.shodan_api_key),
            "nvd": bool(s.nvd_api_key),
        },
    }


def _tool_meta() -> dict[str, dict]:
    """Live name -> {description, gated, intrusive} for every registered tool."""

    out: dict[str, dict] = {}
    for t in mcp._tool_manager.list_tools():
        out[t.name] = {
            "description": t.description or "",
            "gated": getattr(t.fn, "__moonmcp_gated__", False),
            "intrusive": getattr(t.fn, "__moonmcp_intrusive__", False),
        }
    return out


@mcp.tool()
@safe_tool
async def tool_catalog(family: str | None = None) -> dict:
    """Get a self-describing MAP of MoonMCP's own tools — call this second (after
    `server_status`) to orient before you start.

    Groups every tool into a family (setup, passive_osint, light_active,
    intrusive, orchestration, knowledge, reporting, external) with a one-line
    purpose and, crucially, how much each touches the target: `scope_gated`
    (refuses out-of-scope targets) and `intrusive` (needs MOONMCP_ALLOW_INTRUSIVE
    + consent). Also returns the recommended recon→report `workflow`. Pass a
    `family` to drill into one group. Offline — describes the server itself.
    """

    return catalogmod.build_catalog(_tool_meta(), family=family)


@mcp.tool()
@safe_tool
async def scope_list() -> dict:
    """List the current in-scope and out-of-scope entries."""

    ctx = get_context()
    return {"enforced": ctx.scope.enforce, "empty": ctx.scope.is_empty, **ctx.scope.entries()}


@mcp.tool()
@safe_tool
async def scope_add(target: str) -> dict:
    """Authorize a target for active testing.

    Accepts a domain (``example.com`` matches the apex and every subdomain),
    a wildcard (``*.example.com`` for subdomains only), an exact host
    (``api.example.com``), an IP, or a CIDR (``10.0.0.0/8``). Active tools refuse
    to touch anything not covered by the scope.
    """

    ctx = get_context()
    added = ctx.scope.add(target)
    return {"added": added, "scope": ctx.scope.entries()}


@mcp.tool()
@safe_tool
async def scope_exclude(target: str) -> dict:
    """Mark a target as out-of-scope. Exclusions always override the allowlist."""

    ctx = get_context()
    excluded = ctx.scope.exclude(target)
    return {"excluded": excluded, "scope": ctx.scope.entries()}


@mcp.tool()
@safe_tool
async def scope_remove(target: str) -> dict:
    """Remove a previously added scope entry (from allow or deny lists)."""

    ctx = get_context()
    removed = ctx.scope.remove(target)
    return {"removed": removed, "scope": ctx.scope.entries()}


# ---------------------------------------------------------------------------
# programs (bug-bounty engagement profiles)
# ---------------------------------------------------------------------------
def _split_entries(raw: str | None) -> list[str]:
    """Split a comma/space/newline-separated scope string into entries."""

    if not raw:
        return []
    return [e.strip() for e in raw.replace("\n", ",").replace(" ", ",").split(",") if e.strip()]


def _activate_program(ctx: AppContext, prog: Program) -> None:
    """Make *prog* the active engagement: swap the scope to its entries and start
    attaching its header/UA (the HTTP client reads ``programs.active_headers``)."""

    ctx.programs.use(prog.name)
    ctx.scope.clear()
    for entry in prog.scope:
        ctx.scope.add(entry)
    for entry in prog.scope_exclude:
        ctx.scope.exclude(entry)


@mcp.tool()
@safe_tool
async def program_add(name: str, scope: str | None = None, exclude: str | None = None,
                      header: str | None = None, user_agent: str | None = None,
                      note: str = "", activate: bool = True) -> dict:
    """Register a bug-bounty **program / engagement profile** — the tidy way to run
    many programs at once, each with its own scope and its own required header.

    Every program tends to want its own IDENTIFYING header on your traffic so its
    WAF/SOC recognises authorised testing: pass `header` as a raw ``"Name: value"``
    (e.g. ``"X-HackerOne-Research: yourhandle"`` or ``"X-Bug-Bounty: you@example.com"``)
    and, optionally, a per-program `user_agent`. `scope` / `exclude` accept
    comma/space/newline-separated entries (same syntax as `scope_add`). When
    `activate` (default), MoonMCP swaps in this program's scope and auto-attaches
    its header + UA to every in-scope request. Profiles persist across restarts
    when MOONMCP_STATE_DIR is set. Switch later with `program_use`.
    """

    ctx = get_context()
    header_name = header_value = None
    if header:
        header_name, header_value = parse_header(header)
    prog = Program(
        name=name.strip(),
        scope=_split_entries(scope),
        scope_exclude=_split_entries(exclude),
        header_name=header_name,
        header_value=header_value,
        user_agent=(user_agent or None),
        note=note,
    )
    ctx.programs.add(prog)
    result: dict[str, Any] = {"added": prog.name, "program": prog.summary(), "active": False}
    if activate:
        _activate_program(ctx, prog)
        result["active"] = True
        result["scope"] = ctx.scope.entries()
    return result


@mcp.tool()
@safe_tool
async def program_use(name: str) -> dict:
    """Activate a registered program: swap in ITS scope and start attaching its
    bug-bounty header + User-Agent to every in-scope request. See `program_list`
    for the available names.
    """

    ctx = get_context()
    prog = ctx.programs.get(name)
    if prog is None:
        return {"error": "not_found", "detail": f"no program named {name!r}",
                "known": [p.name for p in ctx.programs.list()]}
    _activate_program(ctx, prog)
    return {"active": prog.name, "program": prog.summary(), "scope": ctx.scope.entries()}


@mcp.tool()
@safe_tool
async def program_list() -> dict:
    """List the registered bug-bounty programs and which one is active (with each
    program's scope, bug-bounty header and User-Agent)."""

    ctx = get_context()
    return {
        "active": ctx.programs.active_name,
        "count": len(ctx.programs.list()),
        "programs": [p.summary() for p in ctx.programs.list()],
    }


@mcp.tool()
@safe_tool
async def program_remove(name: str) -> dict:
    """Remove a registered program. If it was active its header/UA stop being
    attached; the current scope is left in place (clear it with scope_remove)."""

    ctx = get_context()
    was_active = ctx.programs.active_name == name
    removed = ctx.programs.remove(name)
    return {"removed": removed, "was_active": was_active,
            "programs": [p.name for p in ctx.programs.list()]}


@mcp.tool()
@safe_tool
async def auth_set(bearer: str | None = None, cookie: str | None = None,
                   basic_user: str | None = None, basic_pass: str | None = None,
                   headers: dict[str, str] | None = None) -> dict:
    """Set the engagement authentication context so the web tools test the
    AUTHENTICATED surface (IDOR/access-control, priv-esc live behind login).

    Provide any of: a `bearer` token, a raw `cookie` string (`k=v; k2=v2`),
    HTTP Basic (`basic_user` + `basic_pass`), or arbitrary `headers`. Values are
    merged into every in-scope request (and only in-scope — the scope guard still
    applies). Credentials are stored in memory for this session only.
    """

    ctx = get_context()
    if bearer:
        ctx.auth.set_bearer(bearer)
    if basic_user is not None and basic_pass is not None:
        ctx.auth.set_basic(basic_user, basic_pass)
    if cookie:
        ctx.auth.set_cookie_string(cookie)
    if headers:
        ctx.auth.update_headers(headers)
    return {"auth": ctx.auth.redacted()}


@mcp.tool()
@safe_tool
async def auth_clear() -> dict:
    """Clear the engagement authentication context (headers + cookies)."""

    ctx = get_context()
    ctx.auth.clear()
    return {"auth": ctx.auth.redacted()}


@mcp.tool()
@safe_tool
async def oast_configure(interaction_domain: str | None = None,
                         poll_url: str | None = None) -> dict:
    """Configure the out-of-band (OAST) interaction server used to confirm BLIND
    vulnerabilities via callbacks. `interaction_domain` is the domain whose
    subdomains are your canaries (e.g. an interactsh self-host or Burp
    Collaborator domain); `poll_url` is its poll API (optionally with a `{token}`
    placeholder). Can also be set via MOONMCP_OAST_DOMAIN / MOONMCP_OAST_POLL_URL.
    """

    ctx = get_context()
    ctx.oast.configure(interaction_domain=interaction_domain, poll_url=poll_url)
    return {"configured": ctx.oast.configured, "interaction_domain": ctx.oast.interaction_domain,
            "poll_url": ctx.oast.poll_url}


@mcp.tool()
@safe_tool
async def oast_selfhost(action: str = "start", port: int = 0, host: str = "127.0.0.1",
                        advertise_host: str | None = None) -> dict:
    """Start a **built-in OAST callback catcher** so blind-vuln confirmation does
    not depend on a third party (interactsh/Collaborator).

    `action`: `start` (launch a threaded HTTP listener; `port=0` picks a free
    port), `stop`, or `status`. Canaries then become `http://<host:port>/<token>`
    and `oast_poll` reads the catcher directly. **The target must be able to reach
    this listener** — the default `host=127.0.0.1` binds loopback (safe; use an
    SSH tunnel / port forward to make it reachable). To bind a public interface,
    pass `host="0.0.0.0"` **and** `advertise_host=<your-public-ip>` (the address
    the canary URLs should point at); binding 0.0.0.0 without advertise_host is
    refused (it opens the listener but makes canaries unreachable). For
    unreachable external targets, use a public interactsh via `oast_configure`.
    """

    ctx = get_context()
    act = action.strip().lower()
    if act == "stop":
        if ctx.oast_server is not None:
            ctx.oast_server.stop()
            ctx.oast_server = None
        ctx.oast.self_host_base = ""
        return {"running": False, "stopped": True}
    if act == "status":
        running = ctx.oast_server is not None and ctx.oast_server.running
        return {"running": running,
                "base": ctx.oast_server.base() if running else None,
                "self_host_base": ctx.oast.self_host_base}
    # start
    if ctx.oast_server is not None and ctx.oast_server.running:
        return {"running": True, "base": ctx.oast_server.base(),
                "note": "already running — stop first to rebind"}
    try:
        server = oastsrvmod.CallbackServer(host=host, port=port, advertise_host=advertise_host)
    except ValueError as exc:
        return {"running": False, "error": "invalid_bind", "detail": str(exc)}
    server.start()
    ctx.oast_server = server
    ctx.oast.self_host_base = server.base()
    ctx.audit.record("oast_selfhost", tool="oast_selfhost", target=server.base(), decision="start")
    return {"running": True, "base": server.base(), "port": server.port,
            "example_canary": f"http://{server.base()}/<token>",
            "note": "target must be able to reach this address; set advertise_host for a public IP."}


@mcp.tool()
@safe_tool
async def oast_generate(label: str = "") -> dict:
    """Mint a unique **callback canary** to embed in a payload for blind-vuln
    detection (blind SSRF/XXE/RCE/SQLi, blind XSS). Returns the canary hostname
    and http/https URLs plus a correlation token; `label` notes where you planted
    it. Poll later with `oast_poll` to see if the target called back. Configure a
    server first with `oast_configure` for a live callback domain.
    """

    ctx = get_context()
    cb = ctx.oast.generate(label=label)
    out = to_dict(cb)
    if not ctx.oast.configured:
        out["note"] = "No OAST server configured — run oast_configure (or set MOONMCP_OAST_DOMAIN)."
    return out


@mcp.tool()
@safe_tool
async def oast_poll(token: str | None = None) -> dict:
    """Poll the configured OAST server for interactions (callbacks) — evidence a
    blind vulnerability fired. Pass a `token` from `oast_generate` to correlate,
    or omit for all. If no poll server is configured, returns the tracked canaries
    so you can check them manually. No target traffic — talks to your OAST server.
    """

    ctx = get_context()
    # Self-host catcher: read interactions straight from the built-in listener.
    if ctx.oast_server is not None and ctx.oast_server.running:
        hits = ctx.oast_server.interactions(token)
        return {"source": "self_host", "token": token, "interaction_count": len(hits),
                "interactions": hits[:200]}
    target = ctx.oast.poll_target(token)
    if target is None:
        return {"configured": ctx.oast.configured,
                "note": "No poll_url configured — set one with oast_configure, or start the "
                        "built-in catcher with oast_selfhost.",
                "canaries": [to_dict(c) for c in ctx.oast.list()]}
    try:
        r = await ctx.http.fetch(target, method="GET", follow_redirects=True)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "poll_url": target}
    if r.status is None:
        return {"error": r.error or "poll request failed", "poll_url": target}
    interactions = oastmod.parse_interactions(r.text())
    return {"token": token, "status": r.status, "interaction_count": len(interactions),
            "interactions": interactions[:200]}


@mcp.tool()
@safe_tool
async def oast_list() -> dict:
    """List the callback canaries minted this session (token, host, URLs, label)."""

    ctx = get_context()
    return {"count": len(ctx.oast.list()), "configured": ctx.oast.configured,
            "canaries": [to_dict(c) for c in ctx.oast.list()]}


# ---------------------------------------------------------------------------
# passive OSINT
# ---------------------------------------------------------------------------
# Passive-OSINT tools live in moonmcp/tools/osint.py (imported below).


# ---------------------------------------------------------------------------
# active (light) — scope-gated
# ---------------------------------------------------------------------------
# Light-active recon tools live in moonmcp/tools/recon_light.py (imported below).


# ---------------------------------------------------------------------------
# web-app checks (light active, scope-gated) + email OSINT
# ---------------------------------------------------------------------------
# Client-source & secret analysis tools live in moonmcp/tools/source_analysis.py (imported below).



# Web-application vulnerability checks live in moonmcp/tools/webcheck.py (imported below).



# Browser-driven tools (screenshot/open/cspp/eval/interact) live in moonmcp/tools/browser_tools.py (imported below).



# Offline artifact-analysis tools (binary/config/depconf/email) live in moonmcp/tools/static_analysis.py (imported below).



# Token / JWT / OAuth probes live in moonmcp/tools/authtoken.py (imported below).



@mcp.tool()
@active_tool(intrusive=True)
async def cache_deception_probe(target: str) -> dict:
    """Test an authenticated page for **web cache deception** — the cache storing
    your private response under an attacker-readable key via a path-confusion
    variant (`/x.css`, `;x.css`, encoded traversal). Pass the URL of a page that
    requires login (set the session with `auth_set` first); it fetches the private
    page authed vs anonymously, then re-reads each crafted variant cookieless and
    flags a leak (confirmed when the cookieless variant also carries a cache-HIT
    header). Intrusive: it primes the cache with your own private page.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await cachedecmod.probe_cache_deception(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def stack_probe(target: str, include_rce_probes: bool = False) -> dict:
    """Fingerprint an in-scope host for high-payout CN/RU enterprise stacks and run
    deterministic, non-destructive unauth checks: Nacos `User-Agent` auth bypass,
    Apache Shiro `rememberMe`, Alibaba Druid monitor exposure, 1C-Bitrix admin,
    and an unauthenticated ClickHouse HTTP interface (point the target at `:8123`).

    The ThinkPHP invokefunction probe sends a **real RCE primitive**
    (`call_user_func_array("md5", ...)`) — a benign `md5()` echo, but the server
    *executes* it. It is therefore opt-in via `include_rce_probes=True`; without
    that flag the ThinkPHP RCE check is skipped and only the passive fingerprint
    runs. Confirmed hits are proofs, not exploits — weaponization goes to Strix.
    Intrusive: it touches known exploit paths.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await stacksmod.probe_stack(ctx.http, url, scope_check=_scope_check(),
                                         include_rce_probes=include_rce_probes)
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def ssrf_metadata_probe(target: str, param: str, method: str = "GET",
                              confirm_creds: bool = False) -> dict:
    """**Response-based** SSRF → cloud-metadata credential theft (the Capital One
    pattern). Injects each provider's instance-metadata URL (AWS / GCP / Azure /
    Alibaba / Yandex / Oracle / DigitalOcean) into `param` and scans the response
    for that provider's credential signature — proving a full-read SSRF that reaches
    the metadata service. Complements the blind `ssrf_probe`. Intrusive; in scope
    only. Header-gated providers (GCP/Azure/Oracle) only leak if the vulnerable
    server forwards our request header.

    **Two tiers:** `confirm_creds=False` (default) runs only the metadata-root
    fingerprint probes (ami-id, instance-id, hostname) — safe detection without
    extracting live credentials. `confirm_creds=True` additionally probes the
    IAM/token endpoints that return real, usable cloud credentials. Run the
    fingerprint first; confirm creds only when you need the proof.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    findings = await ssrfmetamod.probe_ssrf_metadata(
        ctx.http, url, param, method=method, scope_check=_scope_check(),
        confirm_creds=confirm_creds)
    # `findings` always carries the informational "(note)" dry_run entry in default
    # mode, so it is never empty — only an actual leak (verdict="confirmed") means
    # vulnerable. Keying "vulnerable" off bool(findings) reported EVERY probe as a
    # confirmed metadata SSRF, a critical false positive.
    leaks = [f for f in findings if f.get("verdict") == "confirmed"]
    return {
        "target": url, "param": param,
        "vulnerable": bool(leaks), "findings": findings,
        "note": ("full-read SSRF to cloud metadata confirmed — rotate the exposed credentials"
                 if leaks else "no metadata credential signatures reflected in the response"),
    }


@mcp.tool()
@active_tool()
async def crlf_probe(target: str, param: str, method: str = "GET") -> dict:
    """Test a parameter for **CRLF injection / HTTP response splitting**: injects a
    benign marker header (`X-Moonmcp-Inj: 1`) through `param` via CR/LF variants
    (bare-LF, fragment, unicode/overlong, double-encoded, Set-Cookie split) and
    flags a vuln when the marker surfaces as a *real* response header/cookie (not
    body reflection). Non-destructive; in scope only. Common on redirect/`lang`/
    routing params.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    findings = await crlfmod.probe_crlf(ctx.http, url, param, method=method,
                                        scope_check=_scope_check())
    return {"target": url, "param": param, "vulnerable": bool(findings), "findings": findings,
            "note": ("CRLF header injection confirmed" if findings
                     else "no injected header surfaced — parameter appears CR/LF-safe")}


@mcp.tool()
@active_tool(intrusive=True)
async def logic_probe(target: str, param: str | None = None, method: str = "GET",
                      confirm_state_change: bool = False) -> dict:
    """Business-logic ABUSE sweep on an endpoint: **parameter tampering**
    (negative/zero/overflow on money/quantity params — pass `param`, or the
    money/quantity params in the URL query are auto-targeted) + a **mass-assignment**
    check (POSTs privileged fields like role/is_admin/balance and flags reflected
    ones). Returns LEADS (verdict=review) to confirm against the flow — drive it
    with the `business_logic_hunt` prompt. Intrusive; in scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    sc = _scope_check()
    params = [param] if param else logicmod.numeric_params(logicmod.query_keys(url))
    findings: list[dict] = []
    for p in params:
        findings.extend(await logicmod.probe_parameter_tampering(
            ctx.http, url, p, method=method, scope_check=sc))
    findings.extend(await logicmod.probe_mass_assignment(
        ctx.http, url, scope_check=sc, dry_run=not confirm_state_change))
    return {
        "target": url, "tested_params": params, "findings": findings,
        "note": (f"{len(findings)} logic lead(s) — verify the real-world effect against the flow"
                 if findings else "no automatable logic leads; drive the flow per business_logic_hunt"),
    }


@mcp.tool()
@active_tool(intrusive=True)
async def race_probe(target: str, method: str = "POST", n: int = 20,
                     single_packet: bool = True, headers: dict[str, str] | None = None,
                     body: str | None = None,
                     confirm_state_change: bool = False) -> dict:
    """**Race-condition / limit-bypass** probe on a state-changing endpoint (coupon
    apply, vote, withdrawal, invite, signup). By default uses the **single-packet
    attack** (HTTP/1.1 last-byte synchronization) so all N requests complete at the
    server within ~1 ms — neutralizing network jitter, which the naive parallel-fire
    approach can't. Reports how many returned 2xx; >1 on a should-be-once action is a
    race. Engagement `auth_set` cookies/headers are injected automatically; pass extra
    `headers`/`body` as needed. Set `single_packet=False` for the plain asyncio-gather
    fallback. Confirm the side effect actually happened >1×. Intrusive; in scope only.
    """

    from urllib.parse import urlsplit

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    # State-changing gate: the race probe fires N real requests at a should-be-
    # once action. dry_run (default) refuses and describes what would happen.
    if not confirm_state_change:
        return {
            "target": url, "method": method.upper(), "n": n,
            "sent": 0, "success_2xx": 0, "status_histogram": {},
            "verdict": "dry_run",
            "detail": f"would fire {n} parallel {method} requests at {url}; re-run with "
                      "confirm_state_change=True to actually test (WARNING: on a vulnerable "
                      "should-be-once action this performs it up to N times — real side "
                      "effect with no rollback).",
        }
    if single_packet:
        parts = urlsplit(url)
        tls = parts.scheme != "http"
        host = parts.hostname or ""
        port = parts.port or (443 if tls else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        hdrs = {**ctx.auth.merged_headers(), **(headers or {})}
        req = spmod.build_request(host, path, method=method, headers=hdrs, body=(body or ""),
                                  user_agent=ctx.settings.user_agent)
        result = await spmod.single_packet_race(host, port, tls, req, n,
                                                timeout=max(10.0, ctx.settings.timeout),
                                                connect_pin=_connect_pin())
        return {"target": url, "method": method.upper(), **result}
    result = await logicmod.probe_race(ctx.http, url, method=method, n=n,
                                       scope_check=_scope_check(), dry_run=False)
    return {"target": url, "method": method.upper(), "technique": "asyncio-gather", **result}


@mcp.tool()
@active_tool(self_scoped=True, intrusive=True)
async def workflow_probe(steps: list[dict]) -> dict:
    """**Workflow / step-skipping** abuse on a multi-step flow. Pass the flow as an
    ORDERED list of steps — each a dict `{"url", "method"?, "body"?, "success"?}`
    (or a bare URL string) — e.g. cart→address→payment→confirm, or register→verify→
    access. It fetches every step *after the first* cold (without completing the
    prior steps): a flow that enforces its order redirects back / errors, a broken one
    serves the step (order confirmed without payment, account activated without email
    verification). `success` is an optional marker string that positively identifies a
    step's completed content. Returns `review` leads (confirm the business effect).
    Intrusive; in scope only — the steps' hosts are scope-checked.
    """

    ctx = get_context()
    # self_scoped: enforce the intrusive gate + scope + SSRF-resolve guard on EACH
    # step's host (the decorator can't scope-check the steps list itself).
    for s in steps:
        u = s if isinstance(s, str) else (s.get("url") if isinstance(s, dict) else None)
        if u:
            await _require_scope(str(u), intrusive=True, tool="workflow_probe")
    result = await workflowmod.probe_workflow_skip(ctx.http, steps, scope_check=_scope_check())
    n = len(result.get("findings", []))
    result["note"] = (f"{n} step-skipping lead(s) — confirm the business effect of reaching the step "
                      "without its prerequisites" if n
                      else "no step served cold — the flow appears to enforce its sequence")
    return result


@mcp.tool()
@active_tool(self_scoped=True, intrusive=True)
async def second_order_sqli_probe(write: dict, read: list[str] | str, param: str = "comment",
                                  oob: bool = False, wait: float = 3.0,
                                  oast_token: str | None = None) -> dict:
    """**Second-order (stored) SQL injection** — the sink is a DIFFERENT endpoint from
    the injection (a stateless scanner sees nothing). Seed a uniquely-tagged value at
    the `write` endpoint (`{"url","method"?,"body"?}` — inject into `param`, or use a
    `body` template with a `{payload}` placeholder), then drive the `read` endpoint(s)
    and look for a SQL **error** signature that only appears after the seed, or a
    reflected-tag **boolean** differential (equal-length twins, so a verbatim echo gives
    nothing). `oob=True` seeds a tagged OAST payload and polls for a callback. Returns
    `review` leads; extraction → sqlmap `--second-url` / Strix. Intrusive; in scope only.
    """

    ctx = get_context()
    if not isinstance(write, dict) or not write.get("url"):
        return {"error": "invalid_input", "detail": "write must be {'url':..., 'method'?, 'body'?}"}
    w_raw = str(write["url"]).strip()
    w_url = w_raw if "://" in w_raw else f"https://{w_raw}"
    w_method = str(write.get("method") or "POST").upper()
    w_body_tpl = write.get("body")
    w_ctype = write.get("content_type")
    reads = somod.normalize_reads(read)
    for r in reads:
        r["url"] = r["url"] if "://" in r["url"] else f"https://{r['url']}"
    if not reads:
        return {"error": "invalid_input", "detail": "read must be a URL or list of URLs"}

    await _require_scope(w_url, intrusive=True, tool="second_order_sqli_probe")
    for r in reads:
        await _require_scope(r["url"], intrusive=True, tool="second_order_sqli_probe")
    sc = _scope_check()

    async def _write(value: str):
        if isinstance(w_body_tpl, str) and "{payload}" in w_body_tpl:
            hdr = {"Content-Type": w_ctype} if w_ctype else None
            await ctx.http.fetch(w_url, method=w_method, body=w_body_tpl.replace("{payload}", value).encode(),
                                 headers=hdr, follow_redirects=False, scope_check=sc)
        else:
            u, b = injectmod.with_param(w_url, param, value, w_method)
            await ctx.http.fetch(u, method=w_method, body=b, follow_redirects=False, scope_check=sc)

    async def _read_all() -> list:
        obs = []
        for r in reads:
            resp = await ctx.http.fetch(r["url"], method=r["method"], follow_redirects=False, scope_check=sc)
            obs.append(somod.ReadObs(resp.status, resp.text(50_000)))
        return obs

    async def _cycle(value: str) -> list:
        await _write(value)
        return await _read_all()

    tag = somod.make_tag()
    seeds = somod.seed_payloads(tag)
    control = await _cycle(seeds["control"])
    error = await _cycle(seeds["error"])
    # The boolean twins are sent TWICE each so assess_read can measure per-request jitter
    # (a dynamic sink's timestamp/nonce) and require the true/false flip to EXCEED it —
    # a byte-exact length compare false-positived on any dynamic read sink.
    true_r = (await _cycle(seeds["true"]), await _cycle(seeds["true"]))
    false_r = (await _cycle(seeds["false"]), await _cycle(seeds["false"]))

    def _match(t: str) -> list:
        return injmod.match_signatures(t, class_id="sqli")

    findings: list[dict] = []
    for i, r in enumerate(reads):
        hit = somod.assess_read(tag, control[i], error[i],
                                (true_r[0][i], true_r[1][i]), (false_r[0][i], false_r[1][i]), _match)
        if hit:
            findings.append({"read": r["url"], **hit})

    oast_count = 0
    oob_out: dict | None = None
    if oob:
        cb = ctx.oast.get(oast_token) if oast_token else None
        if cb is None and ctx.oast.configured:
            cb = ctx.oast.generate(label="second_order_sqli")
        if cb is None:
            oob_out = {"error": "oast_unconfigured"}
        else:
            await _cycle(somod.oob_seed(tag, cb.http_url, cb.canary_host))
            await asyncio.sleep(max(0.0, min(wait, 8.0)))
            oh, oast_err = await _collect_oast(ctx, cb.token)
            oast_count = len(oh)
            oob_out = {"canary": cb.http_url, "token": cb.token,
                       "interaction_count": oast_count, "interactions": oh[:20]}
            if oast_err:
                oob_out["oast_error"] = oast_err

    has_error = any(f["error_signatures"] for f in findings)
    verdict = confirmmod.evaluate(
        injection_hits=["sqli/second-order" for _ in findings] + (["sqli/second-order-oob"] if oast_count else []),
        reflected=has_error, status_changed=any(f["boolean_differential"] for f in findings),
        oast_count=oast_count)
    out: dict[str, Any] = {"write": w_url, "reads": [r["url"] for r in reads], "tag": tag,
                           **verdict, "findings": findings}
    if oob_out is not None:
        out["oob"] = oob_out
    return out


@mcp.tool()
@active_tool(intrusive=True)
async def value_probe(target: str, param: str | None = None, coupon_code: str | None = None,
                      method: str = "GET",
                      confirm_state_change: bool = False) -> dict:
    """**Value / financial-logic** manipulation on money fields. Auto-targets value
    params in the URL (amount/price/balance/discount/coupon/points/currency…) — or
    pass `param` — and sends the manipulations a correct server must reject: **negative**
    amounts, **zero**, integer **overflow**, sub-cent **precision**, **>100 % discount**,
    and **currency swap/downgrade**. If `coupon_code` is given, also tests single-use
    **coupon/gift-card reuse** (apply the same code repeatedly). Accepted-like-baseline =
    a value-logic lead (verdict `review`; confirm the charged/credited amount). Intrusive;
    in scope only.

    **Coupon-reuse is state-changing** (it redeems the code N times — real financial
    loss, no rollback). `confirm_state_change=False` (default) runs the value/currency
    detection (diff against a baseline) but refuses the coupon-reuse apply, returning a
    `dry_run` verdict. Set `confirm_state_change=True` to actually test coupon reuse.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    sc = _scope_check()
    keys = logicmod.query_keys(url)
    money = [param] if param else valuemod.money_fields(keys)
    findings: list[dict] = []
    for f in money:
        findings.extend(await valuemod.probe_value_tampering(ctx.http, url, f, method=method, scope_check=sc))
    for f in valuemod.currency_fields(keys):
        findings.extend(await valuemod.probe_currency_swap(ctx.http, url, f, method=method, scope_check=sc))
    out: dict = {"target": url, "tested_fields": money, "findings": findings}
    if coupon_code:
        cfields = valuemod.coupon_fields(keys)
        field = cfields[0] if cfields else (param or "coupon")
        out["coupon_reuse"] = await valuemod.probe_coupon_reuse(
            ctx.http, url, field, coupon_code,
            method=(method if method != "GET" else "POST"), scope_check=sc,
            dry_run=not confirm_state_change)
    n = len(findings) + (1 if out.get("coupon_reuse", {}).get("verdict") == "review" else 0)
    out["note"] = (f"{n} value-logic lead(s) — confirm the real charged/credited amount"
                   if n else "no value manipulation accepted; drive the money flow per business_logic_hunt")
    return out


@mcp.tool()
@active_tool()
async def response_leak_probe(target: str, method: str = "GET", data: str | None = None,
                              content_type: str = "application/json") -> dict:
    """Drive an OTP / password-reset / email-verification endpoint and check whether
    the **out-of-band secret leaks in-band**: an OTP, 2FA code, reset token or
    verification link returned in the response body instead of by email/SMS (whoever
    triggers the flow reads it → instant account takeover — a top fintech-API bug).
    Pass `data` (e.g. `{"email":"me@acme.test"}`) to trigger the flow. Secrets are
    **redacted** in the output. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    body = data.encode() if data else None
    headers = {"Content-Type": content_type} if data else None
    findings = await authflowmod.probe_response_leak(
        ctx.http, url, method=method, body=body, headers=headers, scope_check=_scope_check())
    return {
        "target": url, "vulnerable": bool(findings), "findings": findings,
        "note": (f"{len(findings)} in-band secret leak(s) — the OTP/reset secret should be "
                 "delivered out-of-band; confirm it's the real one" if findings
                 else "no in-band OTP/reset secret found in the response body"),
    }


@mcp.tool()
@active_tool()
async def reset_poison_probe(target: str, canary: str | None = None, method: str = "POST",
                             data: str | None = None,
                             content_type: str = "application/json") -> dict:
    """**Password-reset poisoning**: send the reset request with the host-routing
    headers (`Host`, `X-Forwarded-Host`, `Forwarded`, …) set to an attacker host and
    flag any reflected back in the response body / `Location` — a signal the reset
    link is built from a user-controlled host, so the victim's reset token is
    delivered to the attacker (full ATO). Pass `data` (e.g. `{"email":"victim@acme.test"}`);
    omit `canary` to auto-use an OAST host (start `oast_selfhost`/`oast_configure`)
    which also catches a server-side host fetch. The connection stays on the in-scope
    host — only the header is poisoned. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    cb = None
    host = (canary or "").strip()
    if not host:
        if ctx.oast.configured:
            cb = ctx.oast.generate(label="reset_poison")
            host = cb.canary_host or ""
        if not host:
            host = "moonmcp-poison.example"
    body = data.encode() if data else None
    headers = {"Content-Type": content_type} if data else None
    findings = await authflowmod.probe_reset_poison(
        ctx.http, url, host, method=method, body=body, headers=headers,
        scope_check=_scope_check())
    out: dict = {
        "target": url, "canary": host, "reflected": bool(findings), "findings": findings,
        "note": (f"host reflected via {len(findings)} header(s) — verify the reset email's link "
                 "points at the canary" if findings
                 else "no poisoning header was reflected — reset host looks server-fixed"),
    }
    if cb is not None:
        out["oast_token"] = cb.token
        out["oast_note"] = "poll with oast_poll — a callback means the server fetched the poisoned host"
    return out


@mcp.tool()
@active_tool()
async def path_bypass_probe(target: str) -> dict:
    """**403/401 path-normalization bypass**: point at a route that returns 401/403
    and this replays normalization twins (`/admin/..;/`, `/%2e/admin`, matrix `;x`,
    trailing `%2f`/`%2e`, double slash, `%`-encoded char) — a front proxy and the
    backend disagreeing on normalization can skip the ACL while still resolving the
    resource (CVE-2024-0204-class). Flags any twin that flips the status to 2xx
    (verdict `review` — confirm the body is the real protected content). GET-only,
    non-destructive. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await pathnormmod.probe_path_bypass(ctx.http, url, scope_check=_scope_check())
    n = len(result.get("findings", []))
    result["target"] = url
    result["note"] = result.get("note") or (
        f"{n} normalization twin(s) reached the protected route — verify the content"
        if n else "no normalization twin bypassed the ACL")
    return result


@mcp.tool()
@active_tool()
async def debug_exposure(target: str) -> dict:
    """Detect **exposed framework debug pages / consoles** left on in production:
    Laravel Ignition (`/_ignition`), Symfony profiler (`/_profiler`, `/app_dev.php`),
    Laravel Telescope/Horizon, Spring Boot Actuator (`/actuator/env`), Django debug
    toolbar, the Werkzeug/Flask interactive debugger (`/console`), Adminer,
    phpMyAdmin, Rails dev info. Confirms each by a distinctive content signature (no
    soft-404 FPs). Several leak the framework signing secret → feed `analyze_config`
    to classify the forge-to-RCE chain; a couple are direct RCE. GET-only. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    findings = await debugpanelmod.probe_debug_panels(ctx.http, url, scope_check=_scope_check())
    return {
        "target": url, "exposed": bool(findings), "findings": findings,
        "note": (f"{len(findings)} debug panel(s) exposed — pull any leaked APP_KEY/APP_SECRET into "
                 "analyze_config for the forge chain" if findings
                 else "no known framework debug panel exposed"),
    }


@mcp.tool()
@active_tool()
async def recover_sourcemaps(target: str) -> dict:
    """**Recover original source from a shipped `.js.map`.** Give a `.js` or `.js.map`
    URL (or a page): fetches the source map, reconstructs every module's original
    pre-minification source from `sourcesContent[]`, separates app source from vendor
    (`node_modules`/webpack runtime), flags config/secret-looking files, and runs the
    recovered app source through the secret scanner. A shipped source map discloses the
    app's real source tree + hard-coded secrets. `analyze_js` detects the map; this
    recovers it. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    return await sourcemapsmod.recover(ctx.http, url, scope_check=_scope_check())


# Network-fingerprinting tools live in moonmcp/tools/netfp.py (imported below).


# ---------------------------------------------------------------------------
# active (intrusive) — scope-gated + allow_intrusive
# ---------------------------------------------------------------------------
@mcp.tool()
@active_tool(intrusive=True)
async def port_scan(
    target: str,
    ports: str = "top",
    grab_banner: bool = False,
    timeout: float = 2.0,
) -> dict:
    """TCP connect-scan an in-scope host. ``ports`` is 'top' (a curated common
    set) or a spec like '80,443,8000-8100'. Optionally grabs service banners.
    Unprivileged and non-malformed (full handshake). Intrusive: requires
    MOONMCP_ALLOW_INTRUSIVE and the host to be in scope.
    """

    host = normalize_target(target)
    port_list = portsmod.parse_ports(ports)
    if len(port_list) > 5000:
        return {"error": "too_many_ports", "detail": f"{len(port_list)} ports requested; cap is 5000"}
    ctx = get_context()
    result = await portsmod.scan_ports(
        host,
        port_list,
        timeout=timeout,
        # Respect the operator's MOONMCP_MAX_CONCURRENCY safety knob (was silently
        # multiplied by 10, so a configured cap of 20 opened up to 200 sockets); the
        # shared rate limiter still paces total throughput.
        concurrency=max(1, ctx.settings.max_concurrency),
        grab_banner=grab_banner,
        limiter=ctx.governor.limiter,
        connect_pin=_connect_pin(),
    )
    return to_dict(result)


_DB_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def _http_datastore(ctx, host: str, port: int, kind: str, timeout: float) -> dict | None:
    """Fetch the datastore's read-only HTTP path and run its pure interpreter."""

    url = f"http://{host}:{port}{datastoresmod.HTTP_PATHS[kind]}"
    try:
        r = await ctx.http.fetch(url, method="GET", follow_redirects=False,
                                 timeout=timeout, scope_check=_scope_check())
    except Exception:
        return None
    return datastoresmod.HTTP_INTERPRETERS[kind](r.status, r.headers_map(), r.text(20_000))


@mcp.tool()
@active_tool(intrusive=True)
async def db_exposure(target: str, ports: str = "db", timeout: float = 4.0) -> dict:
    """**Unauthenticated datastore exposure sweep** — speaks the minimal read-only
    handshake for each data store and reports which answer with **no auth**. Raw-TCP:
    Redis (`PING`/`INFO`), Memcached (`version`), MongoDB (`listDatabases` wire query).
    HTTP: Elasticsearch/OpenSearch, CouchDB, InfluxDB (`/ping`), Hadoop YARN
    (`/ws/v1/cluster/info`), TiDB status (`/status`). Non-destructive — no writes, no
    dumps, no app submit; exploitation of an exposed store is handed to Strix. `ports`
    is 'db' (the curated DB set), or a spec like '6379,27017' (a host:port target
    probes just that port). Intrusive: requires MOONMCP_ALLOW_INTRUSIVE and scope.
    """

    host, p = _split_host_port(target, 0)
    explicit_port = p if p else None
    ctx = get_context()
    port_list = datastoresmod.ports_to_check(explicit_port, ports)
    result = datastoresmod.DatastoreResult(host=host, checked=port_list)
    sem = asyncio.Semaphore(min(20, max(1, ctx.settings.max_concurrency * 4)))
    limiter = ctx.governor.limiter
    to = max(0.5, min(timeout, 15.0))

    async def _check(port: int) -> dict | None:
        entry = datastoresmod.DB_PORTS.get(port)
        if entry is None:
            return None
        service, kind = entry
        async with sem:
            if limiter is not None:
                await limiter.acquire()
            if kind in datastoresmod.RAW_PROBES:
                hit = await datastoresmod.RAW_PROBES[kind](host, port, to, connect_pin=_connect_pin())
            else:
                hit = await _http_datastore(ctx, host, port, kind, to)
        return {"port": port, "service": service, **hit} if hit else None

    checks = await asyncio.gather(*[_check(p) for p in port_list], return_exceptions=True)
    result.findings = [c for c in checks if isinstance(c, dict)]
    result.findings.sort(key=lambda f: (_DB_SEV_ORDER.get(f["severity"], 5), f["port"]))
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def content_discovery(
    target: str,
    wordlist: list[str] | None = None,
    concurrency: int = 15,
) -> dict:
    """Probe an in-scope host for common sensitive paths (admin panels, API docs,
    .git/.env, backups, config files, ...) using a compact built-in wordlist or a
    caller-supplied one. Reports each path's status, size and content type.
    **Auto-calibrates a soft-404 baseline first** (fetches random paths) and suppresses
    catch-all/SPA echoes, so a hit is a real resource — see `suppressed`/`calibrated` in
    the result. Intrusive: requires MOONMCP_ALLOW_INTRUSIVE and the host to be in scope.
    """

    host, port = _split_host_port(target, 443)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    ctx = get_context()
    result = await contentmod.probe_paths(
        ctx.http, host, scheme=scheme, port=port, wordlist=wordlist,
        concurrency=min(concurrency, ctx.settings.max_concurrency),
        scope_check=_scope_check(),
    )
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def http_methods(target: str) -> dict:
    """Enumerate an in-scope URL's allowed HTTP methods (from OPTIONS) and probe
    sensitive ones (TRACE, PUT, DELETE, PATCH) to flag XST or write-enabled
    endpoints. Intrusive (it sends potentially state-changing methods): requires
    MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await methodsmod.check_methods(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def waf_efficacy(target: str) -> dict:
    """Test how effective an in-scope target's WAF is: sends **benign canary**
    payloads across the common attack categories (XSS, SQLi, LFI, RCE, SSTI,
    traversal, XXE) to see which the WAF blocks, then applies simple transforms
    (case-swap, comment-break, encoding, null-byte) to check whether trivial
    obfuscation bypasses it. Reports protected vs unprotected categories and any
    bypasses. Payloads do nothing harmful. Intrusive: requires
    MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await wafbypassmod.test_waf_efficacy(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def desync_probe(target: str) -> dict:
    """Detection-only HTTP request-smuggling **indicator** probe for an in-scope
    host. Sends single, complete, well-formed requests (no partial/dangling
    requests — nothing is left to poison a connection) to observe how the server
    handles ambiguous framing (both Content-Length + Transfer-Encoding, and
    obfuscated Transfer-Encoding). Reports indicators only — NOT a confirmed
    finding; verify manually with a dedicated tool. Intrusive: requires
    MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await desyncmod.probe_desync(url, timeout=max(10.0, get_context().settings.timeout),
                                          user_agent=get_context().settings.user_agent, connect_pin=_connect_pin())
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def desync_modern_probe(target: str) -> dict:
    """Detection-only probe for **modern (2025 "HTTP/1.1 Must Die") desync**: 0.CL,
    TE.0, `Expect: 100-continue` mishandling and chunk-extension parsing. Uses the
    **timeout-differential** technique — each probe runs on its own fresh
    `Connection: close` socket that is closed immediately, so no second request ever
    shares the connection and **nothing is smuggled to a victim**; it infers which
    length header the server honours from whether it waits for the body it was
    promised. Reports timing indicators only — NOT a confirmed finding (verify with a
    dedicated tool). Intrusive: requires MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await desyncmod.probe_modern_desync(url, timeout=max(6.0, get_context().settings.timeout / 2),
                                                 user_agent=get_context().settings.user_agent, connect_pin=_connect_pin())
    return to_dict(result)


# ---------------------------------------------------------------------------
# findings store
# ---------------------------------------------------------------------------
# Findings management / scoring / reporting live in moonmcp/tools/reporting_tools.py (imported below).



# Knowledge-base tools live in moonmcp/tools/knowledge.py (imported below).


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
@mcp.tool()
@active_tool(self_scoped=True)
async def probe_batch(targets: list[str], fingerprint: bool = True) -> dict:  # noqa: F811
    """Probe a LIST of hosts/URLs in parallel — the enum→probe step of the recon
    loop. Pass the output of `enumerate_subdomains` to find which hosts are live
    and what they run. For each: status, final URL, title and detected tech.

    Out-of-scope or private-resolving targets are skipped with a note; the shared
    rate limiter caps real concurrency. Up to 300 targets per call. In scope only.
    """

    seen: list[str] = list(dict.fromkeys(t.strip() for t in targets if t and t.strip()))[:300]

    async def _one(t: str) -> dict:
        raw = t.strip()
        url = raw if "://" in raw else f"https://{raw}"
        try:
            host = await _require_scope(url, tool="probe_batch")
        except ScopeError as exc:
            return {"target": raw, "skipped": "out_of_scope", "detail": str(exc)}
        ctx = get_context()
        try:
            r = await ctx.http.fetch(
                url, follow_redirects=True, max_redirects=ctx.settings.max_redirects,
                scope_check=_scope_check(),
            )
        except Exception as exc:  # never let one host sink the batch
            return {"target": host, "url": url, "error": f"{type(exc).__name__}: {exc}"}
        entry: dict[str, Any] = {
            "target": host, "url": url, "status": r.status,
            "final_url": r.final_url, "length": len(r.body),
        }
        if r.error:
            entry["error"] = r.error
        if fingerprint and r.status:
            fp = fpmod.fingerprint(r)
            if fp.title:
                entry["title"] = fp.title
            techs = [t.name for t in fp.technologies]
            if techs:
                entry["tech"] = techs
        return entry

    # Bound concurrency so a 300-host batch doesn't launch 300 simultaneous
    # scope-resolve threads / sockets at once.
    sem = asyncio.Semaphore(20)

    async def _guarded(t: str) -> dict:
        async with sem:
            return await _one(t)

    results = await asyncio.gather(*[_guarded(t) for t in seen])
    live = [r for r in results if r.get("status")]
    return {
        "requested": len(seen),
        "live": len(live),
        "skipped": sum(1 for r in results if r.get("skipped")),
        "results": results,
    }


@mcp.tool()
@active_tool()
async def recon_target(domain: str, include_subdomains: bool = True) -> dict:
    """One-shot passive+light recon of an in-scope domain.

    Chains the safe tools into a single report: subdomain enumeration, DNS
    resolution, TLS certificate (with SANs), an HTTP probe, security-header
    grade, and a technology fingerprint of the apex. No intrusive scanning is
    performed. Ideal as the first call against a new target.
    """

    host = normalize_target(domain)
    ctx = get_context()
    report: dict[str, Any] = {"target": host}

    # RECALL: surface what this (or another) agent already learned about the target so
    # the caller can build on it instead of re-deriving — the shared-memory payoff.
    prior = ctx.memory.search("", target=host, limit=10)
    if prior:
        report["prior_memory"] = {
            "count": len(prior),
            "items": [{"kind": p["kind"], "title": p["title"], "trust": p["trust"],
                       "severity": p.get("severity")} for p in prior],
            "note": "already-known facts/findings for this target — build on these, don't re-derive",
        }

    if include_subdomains:
        subs = await submod.enumerate_subdomains(ctx.http, host)
        report["subdomains"] = {"count": subs.count, "sources": subs.sources,
                                "sample": subs.subdomains[:50]}

    dns_res = await dnsmod.resolve(host, http_client=ctx.http)
    report["dns"] = to_dict(dns_res)
    ip = (dns_res.a or [None])[0]

    url = f"https://{host}"
    http_res = await ctx.http.fetch(
        url, follow_redirects=True, max_redirects=ctx.settings.max_redirects, scope_check=_scope_check()
    )
    if http_res.status is not None:
        report["http"] = {
            "final_url": http_res.final_url,
            "status": http_res.status,
            "redirect_chain": http_res.redirect_chain,
            "elapsed_ms": http_res.elapsed_ms,
        }
        report["headers_audit"] = to_dict(headersmod.audit_headers(http_res))
        report["fingerprint"] = to_dict(fpmod.fingerprint(http_res, ip=ip))
    else:
        report["http"] = {"error": http_res.error, "url": url}

    tls_res = await tlsmod.inspect_certificate(host, 443, timeout=ctx.settings.timeout, connect_pin=_connect_pin())
    if tls_res.connected:
        report["tls"] = {
            "issuer": tls_res.issuer.get("organizationName") or tls_res.issuer,
            "not_after": tls_res.not_after,
            "days_until_expiry": tls_res.days_until_expiry,
            "subject_alt_names": tls_res.subject_alt_names,
        }

    email = await emailmod.analyze_email_security(ctx.http, host)
    report["email_security"] = {"grade": email.grade, "spf": bool(email.spf),
                                "dmarc_policy": email.dmarc_policy, "issues": email.issues}
    return report


@mcp.tool()
@active_tool()
async def report(domain: str) -> dict:
    """Run a full safe recon sweep of an in-scope target and return both a
    structured report and a rendered **Markdown** document, with findings
    severity-ranked. Chains: subdomains, DNS, HTTP + fingerprint, security
    headers, TLS, email posture, CORS, WAF, exposed-.git and subdomain-takeover
    checks. No intrusive scanning. In scope only.
    """

    from datetime import datetime, timezone

    host = normalize_target(domain)
    ctx = get_context()
    check = _scope_check()
    apex_url = f"https://{host}"
    findings: list[dict] = []
    surface: dict[str, Any] = {}
    grades: dict[str, str] = {}

    subs = await submod.enumerate_subdomains(ctx.http, host)
    surface["subdomains"] = subs.count

    dns_res = await dnsmod.resolve(host, http_client=ctx.http)
    if dns_res.a:
        surface["ips"] = dns_res.a
    ip = (dns_res.a or [None])[0]

    http_res = await ctx.http.fetch(apex_url, follow_redirects=True,
                                    max_redirects=ctx.settings.max_redirects, scope_check=check)
    if http_res.status is not None:
        fp = fpmod.fingerprint(http_res, ip=ip)
        if fp.technologies:
            surface["technologies"] = [t.name for t in fp.technologies]
        audit = headersmod.audit_headers(http_res)
        grades["Security headers"] = audit.grade
        for m in audit.missing:
            if m.severity in ("high", "medium"):
                findings.append({"severity": m.severity, "title": f"Missing header: {m.header}",
                                 "detail": m.detail})

    email = await emailmod.analyze_email_security(ctx.http, host)
    grades["Email (SPF/DMARC)"] = email.grade
    for issue in email.issues:
        sev = "medium" if ("+all" in issue or "No SPF" in issue or "No DMARC" in issue) else "low"
        findings.append({"severity": sev, "title": "Email posture", "detail": issue})

    cors = await corsmod.audit_cors(ctx.http, apex_url, scope_check=_scope_check())
    for f in cors.findings:
        findings.append({"severity": f.severity, "title": f"CORS: {f.test}",
                         "detail": f.detail, "evidence": f"ACAO={f.acao} creds={f.acac}"})

    vcs = await exposuremod.check_exposure(ctx.http, apex_url, scope_check=check)
    if vcs.git_exposed:
        findings.append({"severity": "high", "title": "Exposed .git directory",
                         "detail": "Source code may be recoverable.",
                         "evidence": vcs.git_remote or ""})

    tko = await takeovermod.check_takeover(ctx.http, host, scope_check=check)
    if tko.vulnerable:
        findings.append({"severity": tko.confidence or "medium",
                         "title": f"Possible subdomain takeover ({tko.service})",
                         "detail": tko.detail, "evidence": tko.matched_fingerprint or ""})

    waf = await wafmod.detect_waf(ctx.http, apex_url, scope_check=check, active=False)
    if waf.detected:
        surface["waf"] = waf.detected

    structured = {"target": host, "surface": surface, "grades": grades, "findings": findings}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    # Persist findings into the session store so they surface via findings://.
    for f in findings:
        ctx.findings.add(target=host, severity=f.get("severity", "info"),
                         title=f.get("title", "finding"), detail=f.get("detail", ""),
                         evidence=f.get("evidence", ""), type="report", source="report",
                         created_at=generated)
    return {"markdown": format_markdown(structured, generated_at=generated), "report": structured}


# Interception (repeater/intruder/passive-scan/history) tools live in moonmcp/tools/interception.py (imported below).


# Behavioural-infrastructure tools live in moonmcp/tools/infra.py (imported below).


# External scanner tools (external_tools/run_scanner/scan_coverage/vuln_scan) moved to moonmcp/tools/scanners.py (imported below).

@mcp.resource("moonmcp://scope")
def scope_resource() -> str:
    """The current authorization scope (read-only view)."""

    import json

    ctx = get_context()
    return json.dumps({"enforced": ctx.scope.enforce, **ctx.scope.entries()}, indent=2)


@mcp.resource("moonmcp://capabilities")
def capabilities_resource() -> str:
    """Detected optional enhancers and external CLI tools."""

    import json

    return json.dumps(
        {
            "dnspython": dnsmod.dnspython_available(),
            "external_tools": {k: v["available"] for k, v in cli.detect_tools().items()},
        },
        indent=2,
    )


@mcp.resource("findings://current")
def findings_resource() -> str:
    """The session's recorded findings (severity-ranked) with a summary."""

    import json

    return json.dumps(get_context().findings.as_dict(), indent=2)


@mcp.resource("audit://recent")
def audit_resource() -> str:
    """The recent audit trail: scope decisions and external commands."""

    import json

    ctx = get_context()
    return json.dumps({"summary": ctx.audit.summary(), "events": ctx.audit.recent(200)}, indent=2)


@mcp.resource("memory://recent")
def memory_resource() -> str:
    """The shared memory hub: stats + the most recent items (trust-labeled)."""

    import json

    ctx = get_context()
    return json.dumps({"stats": ctx.memory.stats(), "recent": ctx.memory.recent(100)}, indent=2)


@mcp.resource("injections://all")
def injections_resource() -> str:
    """The full injection knowledge base: patterns, causes and signatures."""

    import json

    from .knowledge.injections_data import INJECTIONS

    return json.dumps({"stats": injmod.stats(), "injections": INJECTIONS}, indent=2)


@mcp.resource("techniques://all")
def techniques_resource() -> str:
    """The techniques & notable-PoC catalog (referenced index)."""

    import json

    from .knowledge.techniques_data import TECHNIQUES

    return json.dumps({"stats": techmod.stats(), "techniques": TECHNIQUES}, indent=2)


@mcp.resource("privesc://all")
def privesc_resource() -> str:
    """The privilege-escalation knowledge base: techniques + tooling catalog."""

    import json

    from .knowledge.privesc_data import PRIVESC, PRIVESC_TOOLS

    return json.dumps({"stats": privescmod.stats(), "techniques": PRIVESC,
                       "tools": PRIVESC_TOOLS}, indent=2)


@mcp.resource("vulns://all")
def vulns_resource() -> str:
    """The server-side vulnerability catalog + tooling (referenced)."""

    import json

    from .knowledge.vulns_data import SERVER_SIDE_VULNS, VULN_TOOLS

    return json.dumps({"stats": vulnsmod.stats(), "vulns": SERVER_SIDE_VULNS,
                       "tools": VULN_TOOLS}, indent=2)


@mcp.resource("rootcauses://all")
def rootcauses_resource() -> str:
    """The root-cause taxonomy — where the core of all these problems is."""

    import json

    from .knowledge.vulns_data import ROOT_CAUSES

    return json.dumps({"root_causes": ROOT_CAUSES}, indent=2)


@mcp.resource("waf://all")
def waf_resource() -> str:
    """The WAF reference KB: how-it-works, fingerprints and bypass concepts."""

    import json

    from .knowledge.waf_kb_data import WAF_ENTRIES

    return json.dumps({"stats": wafkbmod.stats(), "entries": WAF_ENTRIES}, indent=2)


@mcp.prompt()
def recon_methodology(target: str = "example.com") -> str:
    """A guided, scope-safe reconnaissance methodology for a bug-bounty target."""

    return (
        f"You are performing authorised bug-bounty reconnaissance on `{target}` using MoonMCP.\n"
        "Follow this methodology, staying strictly within authorised scope:\n\n"
        "1. Call `server_status` to see capabilities and current scope.\n"
        f"2. Authorise the target: `scope_add` for `{target}` (and any wildcard the program allows).\n"
        "3. Passive mapping (no packets to target):\n"
        f"   - `enumerate_subdomains` for `{target}`\n"
        f"   - `wayback_urls` for `{target}` to surface old endpoints\n"
        "4. Light active recon on interesting hosts (in scope only):\n"
        "   - `dns_lookup`, then `tls_inspect` (mine the SANs for more hosts),\n"
        "   - `http_probe`, `analyze_headers`, `fingerprint`, `well_known`.\n"
        "5. Map fingerprinted software+versions to CVEs with `cve_search`; look up IPs with `host_intel`.\n"
        "6. Only if the program authorises intrusive testing and MOONMCP_ALLOW_INTRUSIVE is on:\n"
        "   `port_scan`, `content_discovery`, and — if nuclei is installed — `vuln_scan`.\n\n"
        "Summarise findings by severity, always cite the evidence, and never touch out-of-scope hosts."
    )


# Operator system prompts (see moonmcp/prompts.py + docs/SYSTEM_PROMPTS.md).
# These make an agent using MoonMCP plan, pick the right tool, verify before it
# reports, minimise false positives, and stay strictly in authorised scope.
@mcp.prompt()
def bug_bounty_operator(target: str = "example.com", focus: str = "") -> str:
    """Master operator prompt: persona, rules of engagement, control loop and tool map."""

    return promptmod.bug_bounty_operator(target, focus)


@mcp.prompt()
def deep_recon(target: str = "example.com") -> str:
    """Exhaustive, phased attack-surface mapping methodology (TBHM/WSTG-style)."""

    return promptmod.deep_recon(target)


@mcp.prompt()
def injection_hunt(target: str = "example.com", injection_class: str = "") -> str:
    """KB-backed injection hunt: benign canaries, signature confirmation, false-positive discipline."""

    return promptmod.injection_hunt(target, injection_class)


@mcp.prompt()
def technique_advisor(technology: str = "", cve: str = "") -> str:
    """Turn an observed technology/CVE into referenced technique guidance from the catalog."""

    return promptmod.technique_advisor(technology, cve)


@mcp.prompt()
def triage_and_report(target: str = "example.com") -> str:
    """Verify, dedupe, severity-rate and write up findings to accepted-report quality."""

    return promptmod.triage_and_report(target)


@mcp.prompt()
def safe_recon(target: str = "example.com") -> str:
    """Conservative, passive-first, scope-strict recon persona with hard stops."""

    return promptmod.safe_recon(target)


@mcp.prompt()
def privesc_hunt(target: str = "the compromised host", platform: str = "") -> str:
    """KB-backed privilege-escalation triage from an authorised foothold (enumerate → match → verify)."""

    return promptmod.privesc_hunt(target, platform)


@mcp.prompt()
def business_logic_hunt(target: str = "example.com", flow: str = "") -> str:
    """Systematic business-logic flaw methodology (model the flow → enumerate abuses →
    tamper/mass-assign/race → prove the real effect). Pairs with logic_probe/race_probe."""

    return promptmod.business_logic_hunt(target, flow)


def _apply_tool_profile() -> None:
    """Filter the registered tools down to a curated slice when
    ``MOONMCP_PROFILE`` / ``MOONMCP_EXPOSE_TOOLS`` / ``MOONMCP_HIDE_TOOLS`` are set.

    This is how a *curated* MoonMCP is handed to another agent — e.g. embedding
    the knowledge + memory + recon slice (``MOONMCP_PROFILE=strix``) inside a tool
    that already has its own scanners/proxy. Default (no env) exposes everything.
    """

    profile = os.environ.get("MOONMCP_PROFILE")
    expose = _split_entries(os.environ.get("MOONMCP_EXPOSE_TOOLS"))
    hide = _split_entries(os.environ.get("MOONMCP_HIDE_TOOLS"))
    if not (profile or expose or hide):
        return
    tools = mcp._tool_manager._tools
    all_names = set(tools)
    if profile and profile.strip().lower() not in catalogmod.PROFILES:
        import sys
        print(f"[moonmcp] unknown MOONMCP_PROFILE={profile!r}; known: "
              f"{catalogmod.profile_names()} — exposing all", file=sys.stderr)
    allowed = catalogmod.select_profile(all_names, profile=profile, expose=expose, hide=hide)
    for name in all_names - allowed:
        tools.pop(name, None)


_apply_tool_profile()


def run() -> None:
    """Entry point: serve over stdio.

    The application context (and its asyncio primitives) is built lazily on the
    first tool call, i.e. inside the running event loop.
    """

    mcp.run()


if __name__ == "__main__":
    run()
