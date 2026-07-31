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
import re
import secrets
from typing import Any

from . import __version__
from . import catalog as catalogmod
from . import confirm as confirmmod
from . import cvss as cvssmod
from . import intercept as interceptmod
from . import leadpipe as leadpipemod
from . import metrics as metricsmod
from . import obsidian as obsidianmod
from . import prompts as promptmod
from .context import AppContext, to_dict
from .external import cli
from .external import nuclei as nucleimod
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
    _host_key,
    _require_scope,
    _resolve_block,
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
from .recon import binary as binarymod
from .recon import config_audit as configmod
from .recon import content as contentmod
from .recon import crawl as crawlmod
from .recon import datastores as datastoresmod
from .recon import depconf as depconfmod
from .recon import deserialize as deserialmod
from .recon import fingerprint as fpmod
from .recon import firebase as firebasemod
from .recon import gitdump as gitdumpmod
from .recon import headers as headersmod
from .recon import jsendpoints as jsmod
from .recon import jslibs as jslibsmod
from .recon import openapi as openapimod
from .recon import secrets as secretsmod
from .recon import sourcemaps as sourcemapsmod
from .recon import subdomains as submod
from .recon import supabase as supabasemod
from .reporting import TOOL_NAME, format_markdown, format_sarif
from .scope import ScopeError, canonical_ip, normalize_target
from .tools import infra as _infra_tools  # noqa: F401 (registers infra tools)
from .tools import injection as _injection_tools  # noqa: F401 (registers injection probes)
from .tools import knowledge as _knowledge_tools  # noqa: F401 (registers KB tools)
from .tools import memory as _memory_tools  # noqa: F401 (registers memory tools)
from .tools import netfp as _netfp_tools  # noqa: F401 (registers net-fingerprint tools)
from .tools import osint as _osint_tools  # noqa: F401 (registers passive-OSINT tools)
from .tools import recon_light as _recon_light_tools  # noqa: F401 (registers light recon)
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
from .web import authflow as authflowmod
from .web import authz as authzmod
from .web import browser as browsermod
from .web import cache_deception as cachedecmod
from .web import cors as corsmod
from .web import crlf as crlfmod
from .web import cspp as csppmod
from .web import debugpanel as debugpanelmod
from .web import desync as desyncmod
from .web import exposure as exposuremod
from .web import graphql as graphqlmod
from .web import graphqldeep as gqldeepmod
from .web import inject as injectmod
from .web import jwt as jwtmod
from .web import logic as logicmod
from .web import methods as methodsmod
from .web import oauth as oauthmod
from .web import params as paramsmod
from .web import pathnorm as pathnormmod
from .web import redirect as redirectmod
from .web import screenshot as screenshotmod
from .web import secondorder as somod
from .web import singlepacket as spmod
from .web import ssrf_meta as ssrfmetamod
from .web import stacks as stacksmod
from .web import takeover as takeovermod
from .web import value as valuemod
from .web import waf as wafmod
from .web import waf_bypass as wafbypassmod
from .web import websocket as wsmod
from .web import workflow as workflowmod

_HOSTISH_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,63}(?::\d+)?$", re.IGNORECASE)
# Final-label extensions that mean "this is a file/list arg", not a hostname,
# so we don't false-positive a wordlist/config path as a scan target.
_NON_TLD = {
    "txt", "json", "yaml", "yml", "xml", "csv", "html", "htm", "conf", "cfg",
    "ini", "log", "list", "md", "js", "py", "sh", "pdf", "png", "jpg", "toml",
}


# Flags that make a scanner read or write a filesystem path — refused via
# run_scanner so it can't be turned into an arbitrary file read/write that sails
# past the host scope check (which only vets host/URL/IP tokens).
_SCANNER_PATH_FLAGS = {
    "-o", "-oa", "-on", "-ox", "-og", "-os", "-oj", "--output", "-output", "-output-file",
    "-w", "--write", "-config", "--config", "-input-file", "-l", "-list", "-resume",
    "-store-resp", "-srd", "-sr", "-or", "-data-dir", "--stats-file", "-je", "-jle",
    "-sf", "-store-response-dir",
}


def _reject_dangerous_scanner_args(args: list[str]) -> str | None:
    """Return a reason if *args* try to read/write a filesystem path, else None."""

    for tok in args:
        t = tok.strip()
        base = t.split("=", 1)[0].lower()
        if base in _SCANNER_PATH_FLAGS:
            return f"flag '{t}' performs file I/O and is not allowed via run_scanner"
        if "://" in t:
            continue  # a URL, not a path
        if t.startswith(("/", "~", "\\\\")) or ".." in t or (len(t) > 2 and t[1] == ":"):
            return f"path-like argument '{t}' is not allowed via run_scanner"
    return None


def _host_like_tokens(args: list[str]) -> list[str]:
    """Extract host/URL/IP-looking tokens from a CLI arg list (for scope checks).

    Skips flags and non-target tokens (template paths, severities, wordlists) so
    that every actual scan target in ``args`` gets scope-checked.
    """

    import ipaddress

    def _loopback_alias(h: str) -> bool:
        # Well-known loopback hostnames carry no dot+TLD, so `_HOSTISH_RE` misses them,
        # yet they are prime SSRF-to-loopback scan targets (`nmap … localhost`). Extract
        # them explicitly. (Arbitrary single-label names are NOT extracted — that would
        # scope-block benign scanner values like `-tags redis,cve`.)
        hl = h.strip().lower().rstrip(".")
        return (hl in ("localhost", "ip6-localhost", "localhost.localdomain")
                or hl.endswith(".localhost"))

    # Expand comma/whitespace-delimited values so an embedded target (e.g.
    # `-u in-scope.example.com,169.254.169.254`) is scope-checked, not skipped whole.
    # `_HOSTISH_RE` requires a dot+TLD and IPs are matched separately, so tag/status
    # lists (`-tags redis,mongodb`, `-mc 200,301`) never look host-like. A value glued
    # to a flag with '=' (goflags-style `-u=value`, `--target=value`) is the real
    # scope-relevant token — pull it out, else the URL/IP rides to the scanner
    # completely unchecked (an SSRF hole past the scope gate).
    expanded: list[str] = []
    for tok in args:
        t = tok.strip()
        if t.startswith("-"):
            if "=" not in t:
                continue  # a bare flag carries no target
            t = t.split("=", 1)[1].strip()
            if not t or t.startswith("-"):
                continue
        if "," in t or " " in t:
            expanded.extend(p for p in re.split(r"[,\s]+", t) if p)
        elif t:
            expanded.append(t)

    found: list[str] = []
    for tok in expanded:
        t = tok.strip()
        if not t or t.startswith("-"):
            continue
        if "://" in t:
            found.append(t)
            continue
        if "/" in t:
            # A CIDR block is itself a scan target; a host/path (example.com/api)
            # must still have its host scope-checked — don't skip either.
            try:
                ipaddress.ip_network(t, strict=False)
                found.append(t)
                continue
            except ValueError:
                t = t.split("/", 1)[0]
        # Normalise (strip scheme/brackets/port) then test for ANY IP literal —
        # including the obfuscated IPv4 encodings (decimal 2852039166 = 169.254.169.254,
        # hex 0x7f000001, short 127.1) and IPv6 (::1, [::1]) that the old
        # ipaddress.ip_address(t.split(':')[0]) missed and would smuggle to the scanner
        # past the scope check.
        try:
            host_only = normalize_target(t)
        except ValueError:
            continue
        if canonical_ip(host_only) is not None:
            # A dotted/hex/short/IPv6 literal is always a target. A BARE decimal
            # integer also matches benign scanner values (status codes 200/301, ports,
            # counts, rates), so only treat one as a target when it maps to >= 1.0.0.0
            # (0x01000000) — every real obfuscated IP does; small values do not.
            if not host_only.isdigit() or int(host_only) > 0x00FFFFFF:
                found.append(t)
                continue
        if _loopback_alias(host_only):
            found.append(t)
            continue
        if _HOSTISH_RE.match(t) and host_only.rsplit(".", 1)[-1].lower() not in _NON_TLD:
            found.append(t)
    return found


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
@mcp.tool()
@active_tool()
async def crawl(target: str, max_pages: int = 10) -> dict:
    """Lightly crawl an in-scope site (depth 1, bounded) and extract its attack
    surface: internal links, forms + their input names, JavaScript/asset URLs,
    query parameters, external hosts it reaches, and any emails. HTML parsing
    only — no browser. In scope only; redirects that leave scope are not followed.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await crawlmod.crawl(
        ctx.http, url, scope_check=_scope_check(), max_pages=max(1, min(max_pages, 30))
    )
    return to_dict(result)


@mcp.tool()
@active_tool()
async def analyze_js(target: str, max_scripts: int = 15) -> dict:
    """Deep-extract the hidden API surface from a page **and its JavaScript** —
    absolute and relative endpoints/routes that a UI crawl never sees, plus any
    **source maps** (`.map`) that reconstruct the original source. Fetches the
    page, then its same-origin scripts (bounded), and returns a deduped endpoint
    list ready to feed the batch prober / parameter fuzzer. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    return await jsmod.analyze(ctx.http, url, max_scripts=max(1, min(max_scripts, 40)),
                               scope_check=_scope_check())


@mcp.tool()
@safe_tool
async def js_library_scan(sources: list[str]) -> dict:
    """**Known-vulnerable JS library detector** (Retire.js-lite) — matches script
    URLs/filenames (and, best-effort, an in-body version banner) already surfaced
    by `analyze_js`/`crawl` against a small bundled table of historically-
    vulnerable library versions: jQuery <3.5.0 (DOM XSS via `.html()`), AngularJS
    <1.8.0 (CSP/expression-sandbox bypass → XSS), Lodash <4.17.21 (prototype
    pollution), Moment.js <2.29.2 (ReDoS), Handlebars <4.5.3 (prototype-pollution
    RCE gadget), Bootstrap <4.1.2 (tooltip/popover XSS). Pure regex + version
    comparison — no content-hash database (a deliberate zero-dependency trade
    against Retire.js's fuller but harder-to-maintain coverage). Pass the `.url`
    values from `analyze_js`'s `scripts_analysed` (or any script src/JS snippet you
    have) as `sources`. No traffic, no scope needed — scans data you already fetched.
    """

    hits = jslibsmod.scan_all(sources)
    return {"scanned": len(sources), "count": len(hits), "findings": hits}


@mcp.tool()
@active_tool(self_scoped=True)
async def parse_openapi(target: str | None = None, content: str | None = None) -> dict:
    """Parse an OpenAPI/Swagger spec into an endpoint / parameter / method
    inventory — an exposed `openapi.json` / `swagger.json` is a map of the whole
    API attack surface. Pass a `target` URL to fetch the spec (in scope), or paste
    the spec as `content`. Returns every operation (method, path, params, whether
    auth is required, request-body types), the servers, security schemes, and
    flags (operations with NO security, deprecated ops). Feed the paths to
    `probe_batch` and the params to `discover_parameters`.
    """

    if content:
        return openapimod.parse_spec(content)
    if target:
        raw = target.strip()
        url = raw if "://" in raw else f"https://{raw}"
        await _require_scope(url, tool="parse_openapi")
        return await openapimod.fetch_and_parse(get_context().http, url, scope_check=_scope_check())
    return {"error": "invalid_input", "detail": "pass a 'target' URL or inline 'content'"}


@mcp.tool()
@active_tool()
async def extract_secrets(target: str, scan_js: bool = True, max_js: int = 15) -> dict:
    """Fetch an in-scope page (and, by default, its linked JavaScript) and scan
    for exposed secrets: cloud keys (AWS/GCP), API tokens (GitHub, Slack, Stripe,
    Twilio, SendGrid, ...), private keys, JWTs and risky credential assignments.
    Uses high-precision, prefix-anchored patterns; findings are redacted. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    scan = await secretsmod.scan_secrets(
        ctx.http, url, scope_check=_scope_check(), include_js=scan_js,
        max_js=max(1, min(max_js, 40)),
    )
    data = to_dict(scan)
    data["count"] = scan.count
    return data


async def _fetch_app_source(ctx, url: str, sc, max_js: int = 10) -> tuple[str, list[str]]:
    """Fetch a page + its linked JS; return ``(combined_text, sources)`` for scanning
    an app's embedded backend config (Firebase/Supabase)."""

    from urllib.parse import urljoin
    sources: list[str] = []
    parts: list[str] = []
    page = await ctx.http.fetch(url, follow_redirects=True, timeout=12.0, scope_check=sc)
    if page.status is None:
        return "", sources
    html = page.text(500_000)
    final = page.final_url or url
    sources.append(final)
    parts.append(html)
    try:
        _, js, _, _ = crawlmod._extract(final, html)
    except Exception:
        js = set()
    for jm in crawlmod._JS_URL_RE.finditer(html):
        js.add(urljoin(final, jm.group(1)))
    js_files = [u for u in js if u.lower().split("?")[0].endswith(".js")][:max(1, min(max_js, 30))]
    for jurl in js_files:
        if not sc(jurl):
            continue
        jr = await ctx.http.fetch(jurl, follow_redirects=True, timeout=12.0, scope_check=sc)
        if jr.status is None or not jr.body:
            continue
        sources.append(jurl)
        parts.append(jr.text(800_000))
    return "\n".join(parts), sources


@mcp.tool()
@active_tool(self_scoped=True)
async def firebase_exposure(target: str, database_url: str | None = None, max_js: int = 10) -> dict:
    """**Firebase RTDB open-rules** exposure — safe read-only. Harvests
    `databaseURL`/`projectId` from the page + JS `firebaseConfig` (or pass
    `database_url`), then one unauthenticated `GET <databaseURL>/.json?shallow=true`
    (`shallow=true` = top-level keys only, no bulk pull). A 200 with JSON (not
    "Permission denied") = open Security Rules → the whole dataset is readable. A
    discovered `projectId` is reported as a Firestore follow-up lead. Bulk dump → Strix.
    In scope only (the RTDB backend host is scope-checked too).
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    await _require_scope(url, tool="firebase_exposure")
    sc = _scope_check()
    text, sources = await _fetch_app_source(ctx, url, sc, max_js)
    cfg = firebasemod.parse_firebase_config(text)
    if database_url:
        cfg["databaseURL"] = database_url.rstrip("/")
    out: dict[str, Any] = {"target": url, "config": cfg, "sources_scanned": len(sources)}
    db = cfg.get("databaseURL")
    if not db:
        out["verdict"] = "no_firebase_config"
        out["note"] = "no firebaseConfig / databaseURL found in the page or its JS"
        return out
    probe = firebasemod.rtdb_probe_url(db)
    try:
        await _require_scope(probe, tool="firebase_exposure")
    except ScopeError as exc:
        out["verdict"] = "backend_out_of_scope"
        out["note"] = f"discovered RTDB {db} but it is out of scope ({exc}) — add it to scope to test"
        return out
    r = await ctx.http.fetch(probe, follow_redirects=True, timeout=12.0, scope_check=sc)
    out["rtdb_url"] = db
    out["rtdb_status"] = r.status
    finding = firebasemod.assess_rtdb(r.status, r.text(50_000))
    out.update(finding or {"verdict": "inconclusive"})
    if cfg.get("projectId"):
        out["firestore_lead"] = (
            f"projectId '{cfg['projectId']}' — also check Firestore: GET https://firestore."
            f"googleapis.com/v1/projects/{cfg['projectId']}/databases/(default)/documents/<collection>")
    return out


@mcp.tool()
@active_tool(self_scoped=True)
async def supabase_exposure(target: str, project_url: str | None = None, anon_key: str | None = None,
                            max_tables: int = 15, max_js: int = 10) -> dict:
    """**Supabase RLS-off** exposure — safe read-only. Harvests the project URL
    (`https://<ref>.supabase.co`) + the public `anon` key from the app JS (or pass
    `project_url`/`anon_key`), fetches the PostgREST schema at `/rest/v1/?apikey=<anon>`
    to enumerate tables, then `GET /rest/v1/<table>?select=*&limit=1` — a 200 returning a
    row = Row-Level Security OFF (the public key can SELECT the table). Uses the app's own
    public key against its own API; `limit=1`, rows are NOT returned. Bulk dump → Strix.
    In scope only (the Supabase backend host is scope-checked too).
    """

    raw = target.strip()
    app_url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    await _require_scope(app_url, tool="supabase_exposure")
    sc = _scope_check()
    text, sources = await _fetch_app_source(ctx, app_url, sc, max_js)
    cfg = supabasemod.parse_supabase_config(text)
    if project_url:
        cfg["url"] = project_url.rstrip("/")
    if anon_key:
        cfg["anon_key"], cfg["key_type"] = anon_key, "provided"
    out: dict[str, Any] = {"target": app_url, "sources_scanned": len(sources),
                           "project_url": cfg.get("url"), "key_type": cfg.get("key_type")}
    surl, key = cfg.get("url"), cfg.get("anon_key")
    if not surl or not key:
        out["verdict"] = "no_supabase_config"
        out["note"] = "no Supabase URL + anon key found in the page or its JS"
        return out
    try:
        await _require_scope(surl, tool="supabase_exposure")
    except ScopeError as exc:
        out["verdict"] = "backend_out_of_scope"
        out["note"] = f"discovered {surl} but it is out of scope ({exc}) — add it to scope to test"
        return out
    hdr = {"apikey": key, "Authorization": f"Bearer {key}"}
    schema = await ctx.http.fetch(supabasemod.schema_url(surl, key), headers=hdr,
                                  follow_redirects=True, timeout=12.0, scope_check=sc)
    tables = supabasemod.parse_tables(schema.text(200_000))
    out["tables_discovered"] = len(tables)
    open_tables: list[str] = []
    for t in tables[:max(1, min(max_tables, 40))]:
        r = await ctx.http.fetch(supabasemod.table_url(surl, t, key), headers=hdr,
                                 follow_redirects=False, timeout=12.0, scope_check=sc)
        if supabasemod.assess_table(r.status, r.text(50_000)):
            open_tables.append(t)
    out["rls_off_tables"] = open_tables
    if open_tables:
        out.update(verdict="confirmed", severity="high",
                   detail=(f"{len(open_tables)} table(s) readable with the public anon key (RLS off): "
                           f"{', '.join(open_tables[:10])} — full SELECT exposure. Bulk dump → Strix."))
    else:
        out["verdict"] = "no_open_tables"
        out["detail"] = "no table returned a row to the anon key (RLS appears enabled)"
    return out


@mcp.tool()
@active_tool()
async def cors_audit(target: str) -> dict:
    """Test an in-scope URL for CORS misconfigurations: arbitrary-origin
    reflection, 'null' origin acceptance, and prefix/suffix/subdomain bypasses —
    flagged more severely when Access-Control-Allow-Credentials is also true.
    Sends benign GETs with crafted Origin headers. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await corsmod.audit_cors(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def access_control_check(target: str, method: str = "GET", body: str | None = None,
                               second_headers: dict[str, str] | None = None) -> dict:
    """Probe an in-scope URL for broken access control / IDOR by replaying the
    SAME request under multiple identities and diffing the responses:

    - **A** = the current engagement auth (`auth_set` — user A),
    - **B** = `second_headers` if given (a second, lower-priv user's headers/cookies),
    - **anon** = no credentials at all.

    If a protected resource returns a similar 2xx body to the anonymous or the
    other-user request, that is a strong broken-access-control / IDOR signal. The
    verdict is a lead to verify — it reports each identity's status/length and the
    body-similarity so you can judge. Set `auth_set` first for a meaningful A.
    In scope only; sends benign, identical requests (no payloads).
    """

    import hashlib
    from difflib import SequenceMatcher

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    bodyb = body.encode() if body else None
    m = method.upper()

    async def _probe(*, headers=None, suppress_auth=False):
        r = await ctx.http.fetch(url, method=m, headers=headers, body=bodyb,
                                 follow_redirects=False, suppress_auth=suppress_auth)
        snippet = r.body[:4096]
        return {
            "status": r.status,
            "length": len(r.body),
            "sha1": hashlib.sha1(snippet).hexdigest()[:12] if snippet else None,
            "_snippet": snippet,
            "error": r.error,
            "blocked": r.blocked_reason,
        }

    identities: dict[str, dict] = {}
    identities["auth_A"] = await _probe()  # current engagement auth
    if second_headers:
        identities["user_B"] = await _probe(headers=second_headers, suppress_auth=True)
    identities["anonymous"] = await _probe(suppress_auth=True)

    def _similar(a: dict, b: dict) -> float:
        if not a.get("_snippet") or not b.get("_snippet"):
            return 0.0
        return round(SequenceMatcher(None, a["_snippet"], b["_snippet"]).ratio(), 3)

    a = identities["auth_A"]
    concerns: list[str] = []
    comparisons: dict[str, dict] = {}
    for name in ("anonymous", "user_B"):
        other = identities.get(name)
        if not other:
            continue
        sim = _similar(a, other)
        comparisons[f"auth_A_vs_{name}"] = {
            "similarity": sim,
            "same_status": a["status"] == other["status"],
        }
        a_ok = a["status"] is not None and 200 <= a["status"] < 300
        other_ok = other["status"] is not None and 200 <= other["status"] < 300
        if a_ok and other_ok and sim >= 0.95:
            who = "an unauthenticated user" if name == "anonymous" else "a second user"
            concerns.append(
                f"{who} receives a response nearly identical to the authenticated one "
                f"(status {other['status']}, similarity {sim}) — possible broken access "
                f"control / IDOR; verify the resource is meant to be private to user A."
            )

    for v in identities.values():
        v.pop("_snippet", None)
    hint = None if ctx.auth.is_set() else "No engagement auth set — call auth_set first so 'auth_A' is authenticated."
    return {"target": url, "method": m, "identities": identities,
            "comparisons": comparisons, "concerns": concerns,
            "verdict": "review" if concerns else "no_obvious_idor", "hint": hint}


@mcp.tool()
@active_tool()
async def authz_probe(target: str, second_headers: dict[str, str] | None = None,
                      max_refs: int = 8) -> dict:
    """**Multi-step BOLA / IDOR chain** — the object-level authorization test a
    stateless scanner can't do. Set `auth_set` (owner = user A) and optionally pass
    `second_headers` (a lower-priv user B); this runs three GET-only signals:
    (1) **direct** — B/anon get the *same* object from the same URL; (2) **sibling
    sweep** — walk the id space (id±1, low ids) as B/anon and flag any object they
    read; (3) **multi-step chain** — extract the object ids the owner's response
    exposes, then fetch each as B/anon (owner response → cross-identity access).
    Read-only (never mutates — state change → Strix). Findings are `review` leads.
    In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await authzmod.probe_bola(ctx.http, url, b_headers=second_headers,
                                       max_refs=max_refs, scope_check=_scope_check())
    result["hint"] = (None if ctx.auth.is_set()
                      else "No engagement auth set — call auth_set first so the owner (A) is authenticated.")
    n = len(result.get("findings", []))
    result["note"] = (f"{n} object-authorization lead(s) — confirm the body is another user's private "
                      "object" if n else "no cross-identity object access observed")
    return result


@mcp.tool()
@active_tool()
async def graphql_check(target: str) -> dict:
    """Probe an in-scope host for GraphQL endpoints across common paths and test
    whether schema introspection is enabled (which leaks the full API surface).
    In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await graphqlmod.discover_graphql(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def graphql_probe(target: str, endpoint: str | None = None, batch_n: int = 5) -> dict:
    """**Deep GraphQL probing** — the classes that pay out even when introspection is
    OFF. Locates the endpoint (or use `endpoint=` to target one directly), then tests:
    **batch abuse** (an array of queries honoured in one request → rate-limit /
    brute-force amplifier, the batched-login credential-stuffing primitive),
    **field-suggestion schema recovery** (a typo'd field → *"Did you mean …?"* leaks
    real names, recovering the schema without introspection), and **aliases** (many
    operations per document). Nested-traversal **BOLA** is surfaced as a lead to
    confirm with `access_control_check` / Strix. Detection-only — benign queries, small
    batch, no mutations. Run `graphql_check` first for introspection. In scope only.
    """

    ctx = get_context()
    if endpoint:
        url = endpoint if "://" in endpoint else f"https://{endpoint}"
        await _require_scope(url, tool="graphql_probe")
    else:
        raw = target.strip()
        base = raw if "://" in raw else f"https://{raw}"
        disc = await graphqlmod.discover_graphql(ctx.http, base, scope_check=_scope_check())
        found = next((e for e in disc.endpoints if e.is_graphql), None)
        if not found:
            return {"target": target, "is_graphql": False,
                    "review": ["No GraphQL endpoint found on the common paths — pass endpoint= "
                               "if you know it, or run graphql_check."]}
        url = found.url
    result = await gqldeepmod.deep_probe(ctx.http, url, scope_check=_scope_check(),
                                         batch_n=max(2, min(batch_n, 20)))
    return to_dict(result)


@mcp.tool()
@active_tool()
async def ws_probe(target: str, probe_message: bool = False,
                   subprotocol: str | None = None) -> dict:
    """**WebSocket detection** — the surface most scanners skip. Speaks the RFC 6455
    handshake by hand (stdlib) to (1) confirm the URL is a real WebSocket endpoint
    (HTTP 101 + a valid `Sec-WebSocket-Accept`), and (2) run the flagship
    **Cross-Site WebSocket Hijacking (CSWSH)** check: repeat the handshake with a
    *foreign* `Origin` — if the server still upgrades, it doesn't validate Origin, so
    a cookie-authenticated socket is hijackable cross-site. Reports a **lead** (confirm
    the socket is cookie-authenticated and carries sensitive actions before reporting);
    weaponisation is routed to `promote_lead` / Strix.

    Accepts `ws://` / `wss://` (or http(s)/bare host — wss assumed). The handshake is
    as benign as an HTTP GET. `probe_message=True` (opt-in) additionally sends ONE
    clearly-marked benign text frame to check for echo/reflection — off by default so
    nothing is ever delivered into a live socket without consent. In scope only.
    """

    host, port, path, tls = wsmod.split_ws_url(target)
    if not host:
        return {"error": "invalid_target", "detail": f"no host in {target!r}"}
    result = await wsmod.probe_websocket(
        target, host=host, port=port, path=path, tls=tls,
        timeout=max(4.0, get_context().settings.timeout),
        probe_message=probe_message, subprotocol=subprotocol, connect_pin=_connect_pin())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def discover_parameters(target: str, method: str = "GET",
                              wordlist: list[str] | None = None) -> dict:
    """Discover **hidden parameters** on an in-scope URL: probe a wordlist of
    common param names with a benign canary and flag the ones the app reacts to —
    `reflected` (the value echoes back → candidate XSS/SSRF/injection entry point)
    or a behavioural `status-change` / `length-change` (the param is recognised).
    Hidden params are where XSS/SSRF/IDOR/SQLi entry points hide. Pass your own
    `wordlist` to override the defaults; `method` GET or POST. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await paramsmod.discover_parameters(
        ctx.http, url, method=method, wordlist=wordlist, scope_check=_scope_check(),
    )
    return result


@mcp.tool()
@active_tool()
async def waf_detect(target: str) -> dict:
    """Fingerprint an in-scope host's WAF/CDN from response headers, cookies and
    server strings (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, F5, ...). When
    intrusive mode is on, it also sends benign suspicious requests to see whether
    a protective layer trips. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await wafmod.detect_waf(
        ctx.http, url, scope_check=_scope_check(), active=ctx.settings.allow_intrusive
    )
    return to_dict(result)


@mcp.tool()
@active_tool()
async def takeover_check(target: str) -> dict:
    """Check an in-scope subdomain for a potential subdomain takeover: resolves
    the CNAME chain, matches it against a database of takeover-prone providers
    (S3, GitHub Pages, Heroku, Shopify, Azure, ...), and looks for the provider's
    'unclaimed resource' fingerprint (or a dangling DNS record). Results are
    triage signals — verify manually. In scope only.
    """

    host = normalize_target(target)
    ctx = get_context()
    result = await takeovermod.check_takeover(ctx.http, host, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def open_redirect(target: str) -> dict:
    """Test an in-scope URL for open-redirect flaws by injecting an external
    canary into the common redirect parameters (url, next, redirect, returnTo, …)
    and checking whether the server bounces to it via a Location header,
    meta-refresh or JS redirect. Redirects are not followed (the canary is never
    contacted). In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await redirectmod.check_open_redirect(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def trace_redirects(target: str, max_hops: int = 10) -> dict:
    """Follow and analyse an in-scope URL's **redirect chain** hop by hop: each
    hop's status, resolved Location, host and scheme, plus flags for
    `offsite-redirect`, `https-to-http-downgrade`, `redirect-leaves-scope`
    (recorded, not followed), `redirect-loop`, `meta-refresh` and `js-redirect`.
    Useful for auth/OAuth `redirect_uri` flows, SSRF-via-redirect and downgrade
    issues. Off-scope hops are reported but never contacted. In scope only.
    """

    from urllib.parse import urljoin, urlsplit

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    start_host = normalize_target(url)
    ctx = get_context()
    hops: list[dict] = []
    flags: set[str] = set()
    current = url
    seen: set[str] = set()
    final = url
    for _ in range(max(1, min(max_hops, 20))):
        r = await ctx.http.fetch(current, method="GET", follow_redirects=False)
        sp = urlsplit(current)
        hop: dict[str, Any] = {"url": current, "status": r.status,
                               "host": sp.hostname, "scheme": sp.scheme}
        final = current
        if r.status is None:
            hop["error"] = r.error
            hops.append(hop)
            break
        location = r.header("Location") if (300 <= r.status < 400) else None
        if location:
            nxt = urljoin(current, location)
            nsp = urlsplit(nxt)
            hop["location"] = nxt
            in_scope = ctx.scope.is_in_scope(nxt)
            hop["location_in_scope"] = in_scope
            if nsp.hostname and nsp.hostname != sp.hostname:
                flags.add("offsite-redirect")
            if sp.scheme == "https" and nsp.scheme == "http":
                flags.add("https-to-http-downgrade")
            hops.append(hop)
            if nxt in seen:
                flags.add("redirect-loop")
                final = nxt
                break
            seen.add(nxt)
            if not in_scope:
                flags.add("redirect-leaves-scope")  # report, don't follow
                final = nxt
                break
            current = nxt
            continue
        # terminal page — check for client-side redirects
        body = r.text(4096)
        mr = re.search(r'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', body, re.IGNORECASE)
        if mr:
            hop["meta_refresh"] = urljoin(current, mr.group(1))
            flags.add("meta-refresh")
        if re.search(r'(?:window\.)?location(?:\.href|\.replace\(|\s*=)', body, re.IGNORECASE):
            flags.add("js-redirect")
        hops.append(hop)
        break
    return {"start": url, "start_host": start_host, "hop_count": len(hops),
            "final_url": final, "flags": sorted(flags), "hops": hops}


@mcp.tool()
@active_tool()
async def vcs_exposure(target: str) -> dict:
    """Check an in-scope host for exposed VCS/config artefacts (.git, .svn, .hg,
    .env, .DS_Store). Confirms real exposure by validating each file's content
    signature (not just a 200), extracts the git remote URL and recent commit
    log when a .git is exposed. Source disclosure via an exposed .git is
    high-impact. In scope only.
    """

    host, port = _split_host_port(target, 443)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    base = raw if "://" in raw else f"{scheme}://{host}"
    ctx = get_context()
    result = await exposuremod.check_exposure(ctx.http, base, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def git_forensics(target: str, max_objects: int = 60) -> dict:
    """**Git-history forensics** on an exposed `.git` — the deep follow-up to
    `vcs_exposure` and a stable-Critical source. Reconstructs history from what the
    server already serves (read-only GETs; nothing written) and mines it for secrets:

    - `.git/config` remote URLs embedding **credentials** (`user:token@host`),
    - `.git/logs/HEAD` reflog → commit SHAs + **author names/emails** + messages,
    - `.git/index` → the **tracked file list** (flags `.env` / `id_rsa` / `*.sql` /
      `credentials` — what secrets exist), parsed from the binary DIRC format,
    - a **bounded loose-object walk** (`objects/xx/…`, zlib-inflate → commit → tree →
      blob) running the secret scanner over each blob and commit message.

    Packed history (`objects/pack/*.pack`, delta-compressed) is **detected and
    reported**, not parsed — run git-dumper / delegate to Strix for a full clone.
    Secrets are redacted; treat each as a lead (confirm it's live/not rotated).
    `max_objects` caps the walk (default 60). In scope only.
    """

    host, port = _split_host_port(target, 443)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    base = raw if "://" in raw else f"{scheme}://{host}"
    ctx = get_context()
    result, hits = await gitdumpmod.git_forensics(
        ctx.http, base, scope_check=_scope_check(),
        max_objects=max(1, min(max_objects, 300)))
    # Fold the scanner's redacted hits (blobs/config/reflog/messages) into the report.
    for h in hits:
        result.secrets.append({"type": h.type, "source": h.source,
                               "redacted": h.redacted, "fp_risk": h.fp_risk})
    return to_dict(result)


@mcp.tool()
@active_tool()
async def screenshot(target: str, full_page: bool = True, return_base64: bool = False) -> dict:
    """Capture a rendered screenshot of an in-scope page using Playwright +
    Chromium, saved to disk (path returned). Optional and self-degrading: if
    Playwright/Chromium isn't installed, returns a clear note with an install
    hint instead of erroring. Set return_base64 to also inline the PNG. In scope only.
    """

    import tempfile

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    out_dir = ctx.settings.screenshot_dir or __import__("os").path.join(
        tempfile.gettempdir(), "moonmcp-screenshots"
    )
    result = await screenshotmod.capture(
        url, out_dir=out_dir, full_page=full_page, return_base64=return_base64,
        timeout_ms=int(ctx.settings.timeout * 2000),
    )
    return to_dict(result)


def _browser_auth(url: str) -> tuple[dict, list[dict]]:
    """Build (extra_headers, cookies) for the headless browser from the engagement
    auth context, so it drives the target authenticated."""

    ctx = get_context()
    headers = dict(ctx.auth.headers)  # raw headers (Cookie goes via the jar)
    cookies = [{"name": k, "value": v, "url": url} for k, v in ctx.auth.cookies.items()]
    return headers, cookies


@mcp.tool()
@active_tool()
async def browser_open(target: str, capture_html: bool = False,
                       wait_until: str = "load") -> dict:
    """Open an in-scope URL in a headless browser (Playwright + Chromium) and
    return what a real browser sees after JavaScript runs: final URL, status,
    title, the rendered page **text** (and HTML if `capture_html`), plus the
    **console log**, the **network requests** the page made, and any page errors.
    Ideal for JS-heavy SPAs (endpoint/secret discovery) where a raw HTTP fetch
    sees almost nothing. Uses the engagement auth (`auth_set`) so the app is
    driven authenticated. Optional/self-degrading if Playwright is absent.
    `wait_until`: load | domcontentloaded | networkidle. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    headers, cookies = _browser_auth(url)
    result = await browsermod.browse(
        url, capture_html=capture_html, wait_until=wait_until,
        extra_headers=headers, cookies=cookies, scope_ok=_scope_check(),
        resolve_block=_resolve_block(),
    )
    return to_dict(result)


@mcp.tool()
@active_tool()
async def cspp_probe(target: str, wait_until: str = "networkidle") -> dict:
    """**Client-side prototype pollution** — headless-browser detection, safe by design.
    SPAs that parse `location.search`/`location.hash` and deep-merge them can let a
    `__proto__`/`constructor.prototype` URL path write `Object.prototype` in the page's
    JS (the client-side root of DOM-XSS gadget chains). This loads each candidate URL in
    MoonMCP's **own ephemeral browser**, then reads `Object.prototype[<marker>]` back —
    the pollution lands in our throwaway Chromium, **never on the target server** (we send
    an ordinary GET the server ignores) and we send **no engagement auth** (the sink fires
    regardless of login, so nothing leaks). The marker is a fresh random key per run that a
    clean baseline proves absent, so any read-back under a payload is attributable. Tries
    `__proto__`/`constructor` bracket+dotted paths in both query and hash (firing
    `hashchange` for hash-router sinks). Detection-only — proving the sink is reachable, not
    a working XSS; gadget→XSS chaining → Strix. Needs Playwright/Chromium (self-degrades if
    absent). In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    marker = csppmod.MARKER_PREFIX + secrets.token_hex(4)
    read = csppmod.read_script(marker)
    scope_ok = _scope_check()

    async def _read(u, script):
        # No engagement auth on purpose (nothing to leak); scope-gated navigations.
        return await browsermod.browse(u, script=script, capture_text=False,
                                       wait_until=wait_until, scope_ok=scope_ok,
                                       resolve_block=_resolve_block())

    baseline = await _read(url, read)
    if not baseline.available:
        return {"target": url, "available": False, "error": baseline.error,
                "install_hint": baseline.install_hint}
    if baseline.error or baseline.eval_error:
        return {"target": url, "available": True, "verdict": "inconclusive",
                "confidence": "low", "vectors": [],
                "error": baseline.error or baseline.eval_error,
                "note": "could not establish a clean prototype baseline (navigation/eval "
                        "failed) — re-run against a reachable page that returns HTML"}

    hits: list[dict] = []
    for label, vurl, is_hash in csppmod.vectors(url, marker):
        script = csppmod.hashchange_script(marker) if is_hash else read
        r = await _read(vurl, script)
        if csppmod.assess(baseline.eval_result, r.eval_result):
            hits.append({"vector": label, "url": vurl, "value": r.eval_result})

    verdict = confirmmod.evaluate(
        injection_hits=[f"prototype-pollution/client-side ({h['vector']})" for h in hits],
        reflected=bool(hits))
    return {"target": url, "available": True, **verdict,
            "polluted_property": marker if hits else None,
            "vectors": hits, "baseline_marker": baseline.eval_result,
            "note": ("client-side prototype pollution — the page's JS merged a URL "
                     "__proto__/constructor path into Object.prototype (in our own ephemeral "
                     "browser only; the target server is untouched). Locating a gadget → XSS → Strix"
                     if hits else
                     "no client-side prototype-pollution sink reached via URL query/hash "
                     "(the page may pollute from a different source or on a later event)")}


@mcp.tool()
@active_tool()
async def browser_eval(target: str, script: str, wait_until: str = "load") -> dict:
    """Run JavaScript in the page's context — the **browser console** — against an
    in-scope URL and return the (JSON-serialisable) result, plus the console log
    and any page errors. Use it to inspect the live DOM, read `window`/JS state,
    extract data a SPA rendered, or check a JS value. `script` is a JS expression
    (e.g. `document.title`, `Object.keys(window)`, `[...document.querySelectorAll('a')].map(a=>a.href)`).
    Uses the engagement auth. Authorised testing only; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    headers, cookies = _browser_auth(url)
    result = await browsermod.browse(
        url, script=script, capture_text=False, wait_until=wait_until,
        extra_headers=headers, cookies=cookies, scope_ok=_scope_check(),
        resolve_block=_resolve_block(),
    )
    out = to_dict(result)
    # trim the network/text noise — browser_eval is about the script result
    out.pop("html", None)
    out.pop("text", None)
    return out


@mcp.tool()
@active_tool()
async def browser_interact(target: str, actions: list[dict]) -> dict:
    """Drive the headless browser through a sequence of ACTIONS against an in-scope
    URL — click, fill/type inputs, submit forms, wait for selectors, run JS — to
    walk a real user flow (login, multi-step form, SPA navigation). Returns the
    resulting page state (final URL, title, text), per-step results, plus the
    console log, network requests, page errors, **cookies and localStorage**.

    `actions` is a list of dicts, e.g.
    `[{"action":"fill","selector":"#user","value":"a"},
      {"action":"fill","selector":"#pass","value":"b"},
      {"action":"click","selector":"#login"},
      {"action":"wait_for","selector":".dashboard"},
      {"action":"eval","script":"localStorage.getItem('token')"}]`.
    Supported: click, fill, type, press, wait_for, wait, goto (scope-checked),
    eval. Uses the engagement auth. Authorised testing only; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    headers, cookies = _browser_auth(url)
    result = await browsermod.interact(
        url, actions or [], extra_headers=headers, cookies=cookies,
        scope_ok=_scope_check(), resolve_block=_resolve_block(),
    )
    return to_dict(result)


@mcp.tool()
@active_tool()
async def analyze_binary(target: str, decompile: bool = True) -> dict:
    """Download an in-scope compiled artifact (.dll/.exe/.jar/.so/.apk/…) and
    triage it: identify the file type (incl. .NET assemblies), extract ASCII +
    UTF-16 strings, scan them for secrets and for URLs/hosts/connection-strings.
    If it is a .NET assembly and `ilspycmd` is installed, also decompiles a
    preview (else reports how to get it). Great for thick-client / exposed-binary
    recon. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    fetched = await ctx.http.fetch(url, follow_redirects=True, timeout=30.0,
                                   max_body=12 * 1024 * 1024, scope_check=_scope_check())
    if fetched.status is None:
        return {"error": "unreachable", "detail": fetched.error, "url": url}
    if not fetched.body:
        return {"error": "empty_body", "detail": f"HTTP {fetched.status}", "url": url}

    # Run the multi-MB string-extraction + regex scans OFF the event loop — a 12 MiB
    # attacker-controlled artifact must never block every other concurrent MCP tool
    # (matches the crawl/secrets modules' to_thread offload).
    analysis = await asyncio.to_thread(binarymod.analyze_bytes, fetched.body,
                                       url=fetched.final_url or url)
    analysis.truncated = fetched.truncated

    # Optional real decompilation of .NET assemblies via ilspycmd.
    if analysis.is_dotnet:
        path = cli.tool_path("ilspycmd") if ctx.settings.allow_external_tools else None
        if path:
            analysis.decompiler_available = "ilspycmd"
            import os
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".dll", delete=False)
            try:
                tmp.write(fetched.body)
                tmp.close()
                if decompile:
                    res = await cli.run_tool("ilspycmd", [tmp.name],
                                             timeout=min(120.0, ctx.settings.external_timeout),
                                             allow=True)
                    if res.available and res.stdout:
                        analysis.decompiled_preview = res.stdout[:20000]
                    elif res.error:
                        analysis.decompiler_hint = res.error
            finally:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
        else:
            analysis.decompiler_hint = (
                "Install ilspycmd for full decompilation: dotnet tool install -g ilspycmd"
            )
    return to_dict(analysis)


@mcp.tool()
@active_tool(self_scoped=True)
async def analyze_config(content: str | None = None, target: str | None = None,
                         filename: str | None = None) -> dict:
    """Parse a configuration file and lay out **every setting** so you can
    understand the whole config, then flag the risky ones. Supports .env, INI,
    JSON, YAML, .properties, XML (web.config/appsettings), PHP and a generic
    key=value fallback — auto-detected (a `filename` hint helps). Groups settings
    by category (database/secret/cloud/network/debug/…) and reports findings:
    exposed secrets, DEBUG=true, disabled TLS verification, wildcard CORS,
    default/weak credentials, bind-to-all, and credentials in connection strings.

    Pass `content` directly (e.g. from vcs_exposure / analyze_binary output), OR
    a `target` URL to an in-scope config file to fetch and analyze.
    """

    if content is None and not target:
        return {"error": "invalid_input", "detail": "provide 'content' or 'target'"}
    if content is None:
        raw = target.strip()
        url = raw if "://" in raw else f"https://{raw}"
        await _require_scope(url, tool="analyze_config")
        ctx = get_context()
        r = await ctx.http.fetch(url, follow_redirects=True, timeout=15.0,
                                 max_body=2 * 1024 * 1024, scope_check=_scope_check())
        if r.status is None:
            return {"error": "unreachable", "detail": r.error, "url": url}
        if not r.body:
            return {"error": "empty_body", "detail": f"HTTP {r.status}", "url": url}
        content = r.text(limit=2_000_000)
        if filename is None:
            from urllib.parse import urlsplit
            filename = urlsplit(url).path.rsplit("/", 1)[-1] or None
    audit = configmod.analyze_config(content, filename=filename)
    return to_dict(audit)


@mcp.tool()
@safe_tool
async def dependency_confusion(content: str, ecosystem: str = "auto",
                               filename: str | None = None) -> dict:
    """Detect **dependency confusion**: parse a manifest (package.json /
    composer.json / requirements.txt / Pipfile / Gemfile) and existence-check each
    dependency against its PUBLIC registry — a 404 means the name is unclaimed, so
    an attacker could publish a higher-version package your build would pull
    (supply-chain RCE, the Microsoft/Apple pattern). Queries the registry, never
    the target, so no scope is needed. Feed `content` from `vcs_exposure` /
    `analyze_js`; `ecosystem` (npm/pypi/composer/rubygems) auto-detects.
    """

    eco = ecosystem if ecosystem != "auto" else depconfmod.detect_ecosystem(content, filename)
    if eco is None:
        return {"error": "unknown_ecosystem",
                "detail": "could not detect the ecosystem; pass ecosystem=npm|pypi|composer|rubygems"}
    names = depconfmod.parse_dependencies(content, eco)
    if not names:
        return {"ecosystem": eco, "dependencies": 0, "results": [],
                "note": "no dependencies parsed from the manifest"}
    ctx = get_context()
    results = await depconfmod.check_dependencies(ctx.http, names, eco)
    claimable = [r for r in results if r["verdict"] == "claimable"]
    return {
        "ecosystem": eco, "dependencies": len(names), "claimable_count": len(claimable),
        "results": results,
        "note": (f"{len(claimable)} hijack candidate(s) absent on the public registry — "
                 "verify ownership before reporting" if claimable
                 else "all parsed dependencies exist on the public registry"),
    }


@mcp.tool()
@active_tool()
async def email_security(domain: str) -> dict:
    """Analyze a domain's email-spoofing posture over DNS: SPF, DMARC (policy),
    DKIM (common selectors) and CAA, with an A-F grade and specific weaknesses
    (missing/again weak SPF, DMARC p=none, no CAA, ...). Passive DNS. In scope only.
    """

    host = normalize_target(domain)
    ctx = get_context()
    result = await emailmod.analyze_email_security(ctx.http, host)
    return to_dict(result)


@mcp.tool()
@safe_tool
async def jwt_analyze(token: str) -> dict:
    """Decode a JWT (no signature verification) and flag weaknesses: alg=none,
    brute-forceable HS* secrets, missing expiry, jku/x5u/kid key-injection surface,
    and expired/not-yet-valid tokens (checked against the current time). Pure
    parsing — sends no traffic, no scope needed. Triage a token you captured.
    """

    import time

    result = jwtmod.analyze_jwt(token, now_epoch=int(time.time()))
    return to_dict(result)


@mcp.tool()
@safe_tool
async def jwt_crack(token: str, wordlist: list[str] | None = None) -> dict:
    """Offline-brute an HS256/384/512 JWT's signing secret against a weak-secret
    wordlist — a recovered secret lets you forge ANY token (critical). Also returns
    an `alg:none` forgery of the token so you can test whether the server accepts
    unsigned tokens. Pure/offline — sends no traffic, no scope needed.
    """

    secret = jwtmod.crack_hmac_secret(token, wordlist)
    return {
        "hmac_secret_found": secret is not None,
        "secret": secret,
        "severity": "critical" if secret is not None else "info",
        "alg_none_forgery": jwtmod.forge_alg_none(token),
        "note": (f"signing key {secret!r} recovered — forge any token; confirm by replaying"
                 if secret is not None
                 else "no weak secret matched; try a larger wordlist or hashcat -m 16500"),
    }


@mcp.tool()
@safe_tool
async def jwt_alg_confusion(token: str, public_key_pem: str, alg: str = "HS256") -> dict:
    """**JWT algorithm-confusion forgery.** Re-signs `token` as HS256/384/512 using the
    RSA/EC **public key's exact PEM text** as the HMAC secret — the classic
    "verifier doesn't pin the algorithm family" bug, and the highest-impact JWT
    attack after `alg:none`. If the server's JWT library accepts whatever `alg` the
    token declares and reuses the SAME key material to verify both RS*-signed and
    HS*-signed tokens, the forged token validates under the public key alone — full
    forgery without ever touching the private key. Supply `public_key_pem` (the exact
    PEM the server verifies against — fetch it from the JWKS `jwks_uri` `oauth_probe`
    reports, or a captured cert); the original header's `kid` (if any) is preserved so
    a key-by-`kid` lookup still resolves correctly. Offline — never replays the forged
    token itself; do that yourself (or via `http_repeater`) against the protected
    endpoint to confirm. No traffic, no scope needed.
    """

    try:
        forged = jwtmod.forge_alg_confusion(token, public_key_pem, alg=alg)
    except ValueError as exc:
        return {"error": "invalid_input", "detail": str(exc)}
    return {
        "forged_token": forged,
        "algorithm": alg.upper(),
        "note": ("replay this as `Authorization: Bearer <forged_token>` against a protected "
                 "endpoint — acceptance confirms alg-confusion (the verifier reused the public "
                 "key as an HMAC secret)"),
    }


@mcp.tool()
@safe_tool
async def deserialize_fingerprint(blob: str, source: str = "") -> dict:
    """**Deserialization-format fingerprint** (Freddy-lite) — 100% passive. Scans an
    already-captured value (a cookie, header, hidden form field, or body you already
    have) for the byte-level or base64 **signatures** of common object-serialization
    formats: Java native serialization (`ACED0005` / base64 `rO0AB...`), .NET
    ViewState (LosFormatter `FF01` header — also flags whether it looks encrypted vs.
    plaintext), PHP `serialize()` objects (`O:<len>:"Class":`), Python pickle
    (protocol 2-5 markers), Ruby `Marshal.dump`, and Fastjson/Jackson polymorphic
    JSON (`@type`/`@class`). Reports the format + a next-step hint (ysoserial /
    PHPGGC / ViewGen via Strix) — never invokes a gadget chain itself. Pass `source`
    (e.g. `"cookie:session"`, `"hidden-field:state"`) to note where you found it, so
    the report reminds you to confirm it's attacker-reachable. No traffic, no scope
    needed — scans data you already fetched.
    """

    hits = deserialmod.detect_markers(blob)
    return {
        "source": source or ("unspecified — confirm this value is attacker-controlled "
                             "(cookie/header/hidden field) before treating it as a lead"),
        "count": len(hits),
        "findings": [{"format": h.format, "framework": h.framework, "severity": h.severity,
                     "encoding": h.encoding, "detail": h.detail} for h in hits],
    }


@mcp.tool()
@active_tool()
async def oauth_probe(target: str) -> dict:
    """Fetch the OIDC/OAuth discovery document (`/.well-known/openid-configuration`
    or `/.well-known/oauth-authorization-server`) for an in-scope target and flag
    weak configuration: implicit grant enabled, missing/weak PKCE, `alg=none` /
    HS256 signing, plaintext-http issuer, issuer↔jwks host mix-up, public clients.
    One benign GET maps the whole auth surface (endpoints + posture).
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await oauthmod.probe_oidc(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def oauth_redirect_probe(target: str, client_id: str | None = None,
                               authorization_endpoint: str | None = None) -> dict:
    """**OAuth `redirect_uri` bypass chain** — a one-click-ATO class nuclei can't reason
    about. Discovers the `authorization_endpoint` (or pass `authorization_endpoint=`),
    then replays attacker `redirect_uri` variants (attacker-host, subdomain/suffix,
    `@`-host, path-traversal, backslash) at it with **redirects disabled** — a 3xx whose
    `Location` lands on the canary proves the allow-list is bypassable, so an attacker
    steals the auth code/token → account takeover. Supply a known public `client_id`
    for the strongest signal. Benign GETs; the canary is never contacted. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    sc = _scope_check()
    ep = authorization_endpoint
    if not ep:
        oidc = await oauthmod.probe_oidc(ctx.http, url, scope_check=sc)
        ep = oidc.endpoints.get("authorization_endpoint")
    if not ep:
        return {"target": url, "error": "no authorization_endpoint — pass authorization_endpoint= "
                "or a base URL that serves an OIDC discovery document"}
    findings = await oauthmod.probe_redirect_uri_bypass(ctx.http, ep, client_id=client_id, scope_check=sc)
    return {
        "target": url, "authorization_endpoint": ep, "client_id": client_id,
        "vulnerable": bool(findings), "findings": findings,
        "note": ("attacker redirect_uri accepted — confirm the code/token is delivered to it (ATO)"
                 if findings else "no redirect_uri variant landed on the canary"),
    }


@mcp.tool()
@active_tool("target", intrusive=True)
async def jwt_jku_probe(token: str, target: str, header_param: str = "jku",
                        oast_token: str | None = None, wait: float = 2.0) -> dict:
    """**JWT `jku`/`x5u` key-injection (SSRF) probe.** Re-issues `token` with a `jku`
    (or `x5u`) header pointing at a MoonMCP **OAST canary**, replays it to `target` (an
    authed endpoint that verifies the JWT) as `Authorization: Bearer`, and polls for a
    callback — a callback means the server fetched attacker-controlled key material =
    key-injection / SSRF (CVE-2018-0114), a path to full token forgery. Start
    `oast_selfhost`/`oast_configure` first. **Callback-only** — never hosts a valid JWKS;
    weaponization → Strix. Intrusive; in scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    cb = ctx.oast.get(oast_token) if oast_token else None
    if cb is None:
        if not ctx.oast.configured:
            return {"error": "oast_unconfigured",
                    "detail": "start oast_selfhost or oast_configure before probing jku/x5u SSRF"}
        cb = ctx.oast.generate(label="jwt_jku")
    param = "x5u" if header_param.lower() == "x5u" else "jku"
    try:
        forged = jwtmod.forge_remote_key_header(token, cb.http_url, param=param)
    except ValueError:
        return {"error": "invalid_token", "detail": "the supplied token is not a JWT"}
    await ctx.http.fetch(url, method="GET", headers={"Authorization": f"Bearer {forged}"},
                         follow_redirects=False, scope_check=_scope_check())
    await asyncio.sleep(max(0.0, min(wait, 5.0)))
    hits, oast_err = await _collect_oast(ctx, cb.token)
    verdict = confirmmod.evaluate(oast_count=len(hits))
    out = {"target": url, "header_param": param, "canary": cb.http_url, "token_id": cb.token,
           **verdict, "interactions": hits[:20]}
    if oast_err:
        out["oast_error"] = oast_err
        out["note"] = ("could not verify the callback channel — the OAST poll failed, so this is "
                       "NOT a clean no-hit; re-check with oast_poll")
    elif not hits:
        out["note"] = "no callback yet — the server may fetch the key later; re-check with oast_poll"
    return out


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
@mcp.tool()
@safe_tool
async def add_finding(target: str, severity: str, title: str, detail: str = "",
                      evidence: str = "", type: str = "manual") -> dict:
    """Record a finding in the session findings store (severity: critical/high/
    medium/low/info). Findings are also readable via the `findings://current`
    resource and summarised by `report`. In-memory for the session only.
    """

    from datetime import datetime, timezone

    ctx = get_context()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tgt = target.strip().lower()
    # Audit the recording of a finding — findings carry evidence/PII, and the
    # evidentiary trail must show what was recorded, when, and at what severity.
    # (Audit 2026-07-27, SV5: add_finding was the one evidence-bearing op with
    # no audit trail.)
    ctx.audit.record("add_finding", tool="add_finding", target=tgt,
                     decision="record", severity=severity, title=title[:120])
    f = ctx.findings.add(target=tgt, severity=severity, title=title,
                         detail=detail, evidence=evidence, type=type, source="manual",
                         created_at=ts)
    # Mirror into the shared persistent memory hub as a CURATED item — a finding
    # is an asserted conclusion, not raw scraped content.
    mid = ctx.memory.add(kind="finding", title=title, body=(detail or evidence or ""),
                         target=tgt, severity=f.severity, source=type,
                         trust="curated", provenance="manual", tags="finding", created_at=ts)
    # Auto-link into the knowledge graph: a curated finding AFFECTS its host, and
    # (when the target is a URL) is ON a specific endpoint. This turns flat findings
    # into a queryable structure (memory_graph / memory_brief) without extra calls.
    host = _host_key(tgt)
    if host:
        ctx.memory.add_entity(kind="host", name=host, target=host, trust="curated")
        ctx.memory.add_relation(f"finding:{mid}", "affects", f"host:{host}", target=host)
        if "://" in tgt:
            from urllib.parse import urlsplit
            path = urlsplit(tgt).path or "/"
            ctx.memory.add_entity(kind="endpoint", name=path, target=host, trust="curated")
            ctx.memory.add_relation(f"finding:{mid}", "on", f"endpoint:{path}", target=host)
    return {"recorded": to_dict(f), "memory_id": mid, "summary": ctx.findings.summary()}


@mcp.tool()
@safe_tool
async def promote_lead(target: str, kind: str, detail: str = "", evidence: str = "",
                       severity: str = "medium", record: bool = True) -> dict:
    """**Lead → PoC pipeline.** Turn an edge-probe's `review` lead into a confirmation
    plan: classifies the lead by `kind` (e.g. `multistep_bola`, `step_skip`,
    `value_tampering`, `race`, `path_bypass`, `cache_deception`, `sqli`, `ssrf`, …),
    routes it (**confirm_finding** for injection classes, **side-effect
    re-observation** for logic/authz/financial, a **Strix** PoC brief for smuggling),
    and states exactly what "confirmed" looks like. With `record`, files the lead into
    the findings store + shared memory so it's tracked and shared across agents. This is
    the bridge that converts the honest `review` leads into proven findings. Offline; no
    traffic. See `business_logic_hunt` for the hunting side.
    """

    from datetime import datetime, timezone

    ctx = get_context()
    tgt = target.strip()
    plan = leadpipemod.confirmation_plan(kind, tgt, detail)
    out: dict = {"target": tgt, **plan}
    if record:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        store_target = normalize_target(tgt) if "://" in tgt else tgt.lower()
        f = ctx.findings.add(target=store_target, severity=severity,
                             title=f"Lead ({plan['family']}): {plan['kind']} on {tgt}",
                             type="lead", detail=detail, evidence=evidence,
                             source="promote_lead", created_at=ts)
        # A lead is observed/asserted-by-a-tool, not a vetted conclusion → untrusted.
        mid = ctx.memory.add(kind="lead", title=f"{plan['kind']} on {tgt}",
                             body=(detail or evidence or plan["confirmed_when"]),
                             target=store_target, severity=severity, source="promote_lead",
                             trust="untrusted", provenance="tool", tags=f"lead,{plan['family']}",
                             created_at=ts)
        out["recorded"] = {"finding_id": f.id, "memory_id": mid}
    return out


@mcp.tool()
@safe_tool
async def label_finding(finding_id: int, outcome: str) -> dict:
    """Label a recorded finding's real-world **outcome** — `true_positive`,
    `false_positive`, `duplicate`, `wont_fix`, or `unknown` — so `metrics` can compute
    detection precision on the live target. Use it after you verify (or refute) a lead
    on a real app. Offline; no traffic.
    """

    f = get_context().findings.set_outcome(finding_id, outcome)
    if f is None:
        return {"error": "not_found", "finding_id": finding_id,
                "hint": "call list_findings to see recorded ids"}
    return {"labelled": to_dict(f)}


@mcp.tool()
@safe_tool
async def metrics(known_positives: int | None = None) -> dict:
    """**Detection scorecard** for this session — measure how the probes actually do
    on a real target. Aggregates recorded findings by type / severity / source tool /
    outcome, computes **precision** (overall + per source tool) from the outcomes you
    set with `label_finding`, and reports per-tool run counts. Pass `known_positives`
    (your count of real bugs on the target) for a recall figure. Offline; no traffic.
    """

    ctx = get_context()
    runs: dict[str, int] = {}
    for e in ctx.audit.recent(0):  # a gated tool logs an allow'd scope_check per run
        if e.get("decision") == "allow" and e.get("tool"):
            runs[e["tool"]] = runs.get(e["tool"], 0) + 1
    return metricsmod.compute_metrics(ctx.findings.list(), runs=runs,
                                      known_positives=known_positives)


@mcp.tool()
@safe_tool
async def list_findings(target: str | None = None, severity: str | None = None) -> dict:
    """List recorded findings (optionally filtered by target or severity),
    severity-ranked, with a summary count. Reads the session findings store.
    """

    return get_context().findings.as_dict(target=target, severity=severity)


@mcp.tool()
@safe_tool
async def clear_findings(target: str | None = None) -> dict:
    """Clear recorded findings — all of them, or just those for one target."""

    removed = get_context().findings.clear(target=target)
    return {"removed": removed, "summary": get_context().findings.summary()}


@mcp.tool()
@safe_tool
async def triage_findings(apply: bool = False) -> dict:
    """**Deduplicate and prioritise** the session findings — the triage step before
    you write a report.

    Collapses exact-duplicate findings (same type + target + title), ranks the
    unique ones by severity then frequency, and surfaces **systemic** issues (the
    same finding across multiple targets — usually the highest-value report). Returns
    a triage view without changing anything; pass `apply=true` to actually collapse
    the duplicates in the store (evidence/sources are merged into the survivor).
    Feed the result to `report` / `export_findings` / `export_obsidian`.
    """

    ctx = get_context()
    out: dict[str, Any] = {"triage": ctx.findings.triage()}
    if apply:
        out["deduped"] = ctx.findings.dedupe()
        out["triage"] = ctx.findings.triage()
    return out


@mcp.tool()
@safe_tool
async def cvss_score(vector: str | None = None, av: str | None = None, ac: str | None = None,
                     pr: str | None = None, ui: str | None = None, s: str | None = None,
                     c: str | None = None, i: str | None = None, a: str | None = None) -> dict:
    """Compute a **CVSS 3.1 base score** + severity band from a `vector`
    (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and/or individual metrics
    (`av`/`ac`/`pr`/`ui`/`s`/`c`/`i`/`a`), so a confirmed finding carries a
    defensible standard severity. Metrics you omit default to a conservative
    low-impact base (C/I/A = None). Offline — pure calculation.
    """

    metrics = {k: v for k, v in (("AV", av), ("AC", ac), ("PR", pr), ("UI", ui),
                                 ("S", s), ("C", c), ("I", i), ("A", a)) if v}
    return cvssmod.base_score(metrics or None, vector=vector)


# Shared-memory-hub tools live in moonmcp/tools/memory.py (imported below).


@mcp.tool()
@safe_tool
async def audit_log(limit: int = 100, event: str | None = None) -> dict:
    """Read the session **audit trail** — one record per scope decision (allow /
    deny / SSRF-block / intrusive-block) and external command. Optionally filter by
    `event`. Also on the `audit://recent` resource, and persisted to JSONL when
    MOONMCP_AUDIT_LOG is set. Use it to review exactly what the agent touched.
    """

    ctx = get_context()
    events = ctx.audit.recent(max(1, min(limit, 1000)))
    if event:
        events = [e for e in events if e.get("event") == event]
    return {"summary": ctx.audit.summary(), "count": len(events), "events": events}


@mcp.tool()
@safe_tool
async def export_obsidian(out_dir: str | None = None, include_kb: bool = True,
                          canvas: bool = True, engagement: str = "engagement",
                          dedupe: bool = True) -> dict:
    """Export the session into an **Obsidian vault** as a navigable knowledge
    graph: a Home MOC, one note per asset and finding (cross-linked, tagged by
    severity), and — with `include_kb` — the knowledge bases as a linked web
    (each vulnerability `[[wikilinks]]` to its **root cause**), plus an Obsidian
    **Canvas** (`.canvas`) graph. Also emits a Graphify-style `graph.json`
    (NetworkX node-link, provenance-tagged edges) and a `GRAPH_REPORT.md`
    ("god nodes"). By default `dedupe` collapses duplicate findings first so the
    graph stays clean. Open the folder as a vault and use the graph view. Writes to
    `out_dir` (or MOONMCP_VAULT_DIR, else ./moonmcp-vault); pure files, no network.
    """

    import os

    ctx = get_context()
    root = out_dir or os.environ.get("MOONMCP_VAULT_DIR") or os.path.join(os.getcwd(), "moonmcp-vault")
    src = ctx.findings.unique() if dedupe else ctx.findings.list()
    findings = [
        {"id": f.id, "target": f.target, "severity": f.severity, "title": f.title,
         "type": f.type, "detail": f.detail, "evidence": f.evidence, "created_at": f.created_at}
        for f in src
    ]
    inj = vulns = rc = tech = None
    if include_kb:
        from .knowledge.injections_data import INJECTIONS as inj
        from .knowledge.techniques_data import TECHNIQUES as tech
        from .knowledge.vulns_data import ROOT_CAUSES as rc
        from .knowledge.vulns_data import SERVER_SIDE_VULNS as vulns
    manifest = obsidianmod.build_vault(
        root, engagement=engagement, findings=findings, injections=inj, vulns=vulns,
        root_causes=rc, techniques=tech, want_canvas=canvas,
    )
    if dedupe:
        manifest["duplicates_folded"] = len(ctx.findings.list()) - len(src)
    ctx.audit.record("export_obsidian", tool="export_obsidian", target=root, decision="write")
    return manifest


@mcp.tool()
@safe_tool
async def surface_diff(name: str, items: list[str]) -> dict:
    """Track how the attack surface **changes** over time. Pass a snapshot `name`
    (e.g. `acme-subdomains`) and the current list of `items` (subdomains, live
    hosts, endpoints, params). The first call sets the baseline; every later call
    returns only what was **added** / **removed** since last time — the fresh,
    under-competed surface. Persists across runs if MOONMCP_STATE_DIR is set.
    """

    return get_context().snapshots.diff(name, items)


@mcp.tool()
@safe_tool
async def surface_snapshots(clear: str | None = None) -> dict:
    """List the tracked surface snapshots (name → item count), or clear one by
    name (or all with `clear="*"`).
    """

    ctx = get_context()
    if clear is not None:
        removed = ctx.snapshots.clear(None if clear == "*" else clear)
        return {"cleared": removed, "snapshots": ctx.snapshots.names()}
    return {"snapshots": ctx.snapshots.names()}


@mcp.tool()
@safe_tool
async def export_findings(format: str = "sarif", target: str | None = None,
                          severity: str | None = None) -> dict:
    """Export the recorded findings in a machine-readable format for CI / triage.

    `format`: `sarif` (SARIF 2.1.0 — GitHub code-scanning / most DAST pipelines)
    or `json` (the raw findings + summary). Optionally filter by `target` /
    `severity`. Returns the document inline; no network.
    """

    ctx = get_context()
    fmt = format.strip().lower()
    findings = [
        {"id": f.id, "target": f.target, "severity": f.severity, "title": f.title,
         "type": f.type, "detail": f.detail, "evidence": f.evidence,
         "source": f.source, "created_at": f.created_at}
        for f in ctx.findings.list(target=target, severity=severity)
    ]
    if fmt == "json":
        return {"format": "json", "summary": ctx.findings.summary(), "findings": findings}
    if fmt == "sarif":
        return {"format": "sarif", "sarif": format_sarif(findings, version=__version__)}
    return {"error": "invalid_input", "detail": f"unknown format '{format}' (use sarif or json)"}


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


# ---------------------------------------------------------------------------
# interception (Burp-style repeater / intruder / passive scan / history)
# ---------------------------------------------------------------------------
def _record_exchange(source: str, method: str, url: str, req_headers: dict,
                     req_body: bytes, result: Any, label: str = "") -> int:
    """Store a request/response pair in the session history; return its id."""

    ctx = get_context()
    ex = ctx.history.add(
        source=source, method=method, url=url, host=normalize_target(url),
        status=result.status, req_headers=req_headers or {}, req_body=req_body or b"",
        resp_headers=result.headers_map(), resp_body=result.body,
        resp_len=len(result.body), elapsed_ms=result.elapsed_ms, label=label,
    )
    return ex.id


@mcp.tool()
@active_tool(self_scoped=True)
async def http_repeater(url: str | None = None, method: str = "GET",
                        headers: dict[str, str] | None = None, body: str | None = None,
                        raw: str | None = None, follow_redirects: bool = False,
                        passive: bool = True, label: str = "") -> dict:
    """**Repeater** — send one fully-controlled HTTP request to an in-scope target
    and get the complete response back, so you can iterate on a payload.

    Provide either a `raw` HTTP/1.1 request (Burp-style: request line + headers +
    blank line + body; absolute URL or a `Host:` header) OR the structured form
    (`url` + `method` + `headers` + `body`). Returns status, response headers, the
    body (preview) and timing; by default also a quick `passive` scan (header
    grade, tech fingerprint, secret hits). Each call is recorded to `http_history`
    for replay. In scope only.
    """

    if raw:
        method, url, parsed_headers, body_bytes = interceptmod.parse_raw_request(raw)
        merged_headers = {**parsed_headers, **(headers or {})}
    else:
        if not url or not url.strip():
            return {"error": "invalid_input", "detail": "pass a 'url' or a 'raw' request"}
        raw_t = url.strip()
        url = raw_t if "://" in raw_t else f"https://{raw_t}"
        merged_headers = headers or {}
        body_bytes = body.encode() if body else None

    await _require_scope(url, tool="http_repeater")
    ctx = get_context()
    result = await ctx.http.fetch(
        url, method=method, headers=merged_headers or None, body=body_bytes,
        follow_redirects=follow_redirects, max_redirects=ctx.settings.max_redirects,
        scope_check=_scope_check(),
    )
    ex_id = _record_exchange("repeater", method, url, merged_headers, body_bytes or b"",
                             result, label=label)
    out: dict[str, Any] = {
        "exchange_id": ex_id,
        "request": {"method": method, "url": url, "headers": merged_headers},
        "status": result.status,
        "reason": result.reason,
        "response_headers": result.headers_map(),
        "response_body_preview": result.text(4096),
        "response_bytes": len(result.body),
        "elapsed_ms": result.elapsed_ms,
    }
    if result.header("Location"):
        out["location"] = result.header("Location")
    if result.error:
        out["error"] = result.error
    if passive and result.status is not None:
        # Off the event loop: passive_findings runs the secret-scan regexes over up to
        # 500 KB of the (in-scope but attacker-controlled) response body — a large body
        # must not block concurrent tools (matches the crawl/secrets/binary offloads).
        out["passive"] = await asyncio.to_thread(interceptmod.passive_findings, result)
    return out


@mcp.tool()
@active_tool(self_scoped=True, intrusive=True)
async def intruder(template: str, payloads: list[str], marker: str = "§",
                   method: str = "GET", headers: dict[str, str] | None = None,
                   body: str | None = None, max_requests: int = 100) -> dict:
    """**Intruder** — fire a request `template` once per payload, substituting the
    `marker` (default `§`) with each payload, and diff the responses.

    Put the marker where the payload goes, e.g. ``https://host/search?q=§`` (or in
    `body` for POST). Returns, per payload: status, length, whether the payload was
    reflected in the response, and anomaly `flags` (status-change / length-outlier
    / reflected) versus a no-payload baseline — the leads for injection/IDOR entry
    points. Payloads are URL-encoded into the URL; the shared rate limiter caps
    real concurrency. Up to `max_requests` payloads. **Intrusive** (needs
    MOONMCP_ALLOW_INTRUSIVE) and in scope only.
    """

    from urllib.parse import quote

    if marker not in template and not (body and marker in body):
        return {"error": "invalid_input",
                "detail": f"marker {marker!r} not found in template or body"}
    base_url = template.replace(marker, "")
    raw_t = base_url.strip()
    base_url = raw_t if "://" in raw_t else f"https://{raw_t}"
    # Intruder is intrusive: this gates on MOONMCP_ALLOW_INTRUSIVE + scope.
    await _require_scope(template.replace(marker, ""), intrusive=True, tool="intruder")
    ctx = get_context()

    async def _one(payload: str) -> dict:
        enc = quote(payload, safe="")
        url = (template if "://" in template else f"https://{template}").replace(marker, enc)
        req_body = (body.replace(marker, payload).encode() if body else None)
        if not ctx.scope.is_in_scope(url):
            return interceptmod.IntruderResult(payload=payload, status=None, length=0,
                                               elapsed_ms=0.0, reflected=False,
                                               error="out_of_scope").__dict__
        try:
            r = await ctx.http.fetch(url, method=method, headers=headers, body=req_body,
                                     follow_redirects=False, scope_check=_scope_check())
        except Exception as exc:
            return interceptmod.IntruderResult(payload=payload, status=None, length=0,
                                               elapsed_ms=0.0, reflected=False,
                                               error=f"{type(exc).__name__}: {exc}").__dict__
        reflected = bool(payload) and payload.encode() in r.body
        return interceptmod.IntruderResult(
            payload=payload, status=r.status, length=len(r.body),
            elapsed_ms=r.elapsed_ms, reflected=reflected).__dict__

    # Baseline (empty payload) for diffing.
    base = await _one("")
    todo = list(dict.fromkeys(p for p in payloads if p))[:max(1, min(max_requests, 500))]
    results = await asyncio.gather(*[_one(p) for p in todo])

    base_status, base_len = base.get("status"), base.get("length", 0)
    for r in results:
        flags: list[str] = []
        if r.get("status") != base_status:
            flags.append("status-change")
        if base_len and abs(r.get("length", 0) - base_len) > max(50, base_len * 0.25):
            flags.append("length-outlier")
        if r.get("reflected"):
            flags.append("reflected")
        r["flags"] = flags
    interesting = [r for r in results if r["flags"] and not r.get("error")]
    return {
        "target": base_url,
        "baseline": {"status": base_status, "length": base_len},
        "sent": len(results),
        "interesting_count": len(interesting),
        "interesting": interesting[:100],
        "results": results[:200],
    }


@mcp.tool()
@active_tool("target")
async def passive_scan(target: str) -> dict:
    """**Passive scan** — fetch an in-scope URL once and run all of MoonMCP's
    passive analysers over the response in one call: HTTP security-header grade +
    issues, technology fingerprint, and exposed-secret hits (redacted). No probing
    or payloads — a single benign GET. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await ctx.http.fetch(
        url, follow_redirects=True, max_redirects=ctx.settings.max_redirects,
        scope_check=_scope_check(),
    )
    if result.status is None:
        return {"error": "unreachable", "detail": result.error, "url": url}
    _record_exchange("passive_scan", "GET", url, {}, b"", result)
    # Run the passive analysers (incl. the up-to-500 KB secret scan) off the event loop.
    pf = await asyncio.to_thread(interceptmod.passive_findings, result)
    return {"url": result.final_url or url, "status": result.status, **pf}


@mcp.tool()
@safe_tool
async def http_history(exchange_id: int | None = None, host: str | None = None,
                       limit: int = 50, clear: bool = False) -> dict:
    """Review the **request/response history** captured by `http_repeater`,
    `intruder` and `passive_scan` (like Burp's history). Pass an `exchange_id` for
    the full recorded pair, `host` to filter, `clear=true` to wipe. No traffic —
    reads the in-memory session log.
    """

    ctx = get_context()
    if clear:
        return {"cleared": ctx.history.clear()}
    if exchange_id is not None:
        ex = ctx.history.get(exchange_id)
        return to_dict(ex) if ex else {"error": "not_found", "detail": f"no exchange #{exchange_id}"}
    items = ctx.history.list(limit=limit, host=host)
    return {
        "count": ctx.history.count,
        "shown": len(items),
        "exchanges": [
            {"id": e.id, "source": e.source, "method": e.method, "url": e.url,
             "status": e.status, "resp_bytes": e.resp_len, "elapsed_ms": e.elapsed_ms,
             "label": e.label}
            for e in items
        ],
    }


# Active injection/exploitation probes live in moonmcp/tools/injection.py (imported below).
# Behavioural-infrastructure tools live in moonmcp/tools/infra.py (imported below).


# ---------------------------------------------------------------------------
# external CLI integration
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def external_tools(category: str | None = None) -> dict:
    """List the external security CLIs MoonMCP knows about — **grouped by
    category** (subdomain, dns, http, crawl, content, port, vuln, cms, tls, url,
    decompile) — with, for each: whether it is installed on PATH, its native
    MoonMCP fallback, whether it is `intrusive` (gated), and an install hint.

    On Kali most of these are already present. Call this before `run_scanner` /
    `vuln_scan` to see what is available and what to install. Pass a `category` to
    filter. `by_category` groups the same data for quick scanning.
    """

    s = get_context().settings
    grouped = cli.tools_by_category()
    if category:
        grouped = {category: grouped.get(category, [])}
    installed = sorted(n for n, m in cli.detect_tools().items() if m["available"])
    return {
        "runner_enabled": s.allow_external_tools,
        "intrusive_enabled": s.allow_intrusive,
        "installed": installed,
        "installed_count": len(installed),
        "known_count": len(cli.KNOWN_TOOLS),
        "by_category": grouped,
    }


@mcp.tool()
@active_tool(self_scoped=True)
async def run_scanner(tool: str, args: list[str], target: str | None = None) -> dict:
    """Run an installed external security CLI and return its output.

    ``tool`` must be one of the known tools — see `external_tools` for the full,
    categorised list (subfinder, amass, httpx, whatweb, wafw00f, katana,
    gau/waybackurls, ffuf/feroxbuster/gobuster, naabu/nmap/masscan,
    nuclei/nikto/wpscan/sqlmap/dalfox, sslscan/tlsx, …). ``args`` are passed
    through verbatim. If ``target`` is given it is scope-checked first; every
    host/URL in ``args`` is scope-checked too. **Intrusive** scanners (fuzzers,
    port scanners, active vuln scanners) also require MOONMCP_ALLOW_INTRUSIVE. If
    the tool is missing, returns the native MoonMCP fallback to use instead. JSONL
    output is auto-parsed. Gated by MOONMCP_ALLOW_EXTERNAL_TOOLS.
    """

    ctx = get_context()
    if tool not in cli.KNOWN_TOOLS:
        return {"error": "unknown_tool", "detail": f"{tool} is not a known scanner",
                "known": list(cli.KNOWN_TOOLS)}
    # Intrusive external scanners are gated exactly like the native intrusive
    # tools — scope alone is not enough for a fuzzer/port-scanner/active scanner.
    if cli.is_intrusive(tool) and not ctx.settings.allow_intrusive:
        ctx.audit.record("intrusive_blocked", tool="run_scanner", target=(target or tool),
                         decision="deny")
        return {"error": "disabled",
                "detail": f"{tool} is an intrusive scanner; enable with MOONMCP_ALLOW_INTRUSIVE=1."}
    # Refuse file-I/O flags/paths: run_scanner is a network-recon passthrough, not
    # a way to read/write arbitrary files past the host scope check.
    bad = _reject_dangerous_scanner_args(args)
    if bad is not None:
        return {"error": "unsafe_args", "detail": bad,
                "hint": "run_scanner is for network recon only; file input/output flags are blocked."}
    # Scope-check the declared target AND every host/URL/IP in args — the real
    # scan target usually lives inside args (e.g. `-u https://host`).
    to_check = ([target] if target else []) + _host_like_tokens(args)
    if ctx.settings.enforce_scope and not to_check:
        return {"error": "no_target",
                "detail": "Refusing to run a scanner with no scope-checked target while "
                          "enforcement is on. Pass a 'target' that is in scope, or include the "
                          "host/URL in args."}
    for t in to_check:
        await _require_scope(t, tool="run_scanner")
    ctx.audit.record("external_tool", tool=tool, target=(target or ",".join(to_check)),
                     decision="run", args=args[:20])
    result = await cli.run_tool(
        tool, args, timeout=ctx.settings.external_timeout, allow=ctx.settings.allow_external_tools
    )
    data = to_dict(result)
    if result.available and result.stdout:
        parsed = cli.parse_jsonl(result.stdout)
        if parsed:
            data["parsed"] = parsed[:500]
    return data


@mcp.tool()
@safe_tool
async def scan_coverage() -> dict:
    """**What nuclei covers vs. what only MoonMCP does** — the honest, executable map.

    nuclei is a stateless per-template matcher: because everyone mass-scans with it,
    the bugs it can find are largely already reported. This returns the split so you
    scan efficiently: `delegate_to_nuclei` (commodity — run `vuln_scan`, don't hand-
    hunt it), `native_edge` (the stateful/differential/timing/logic probes nuclei
    STRUCTURALLY can't express — higher hit-rate on already-scanned targets, always
    run these), plus MoonMCP's architecture edge. Offline; no traffic.
    """

    return nucleimod.coverage_report()


@mcp.tool()
@active_tool(intrusive=True)
async def vuln_scan(target: str, templates: str | None = None, severity: str | None = None,
                    tags: str | None = None, dast: bool = False, record: bool = False) -> dict:
    """Run a nuclei template-based vulnerability scan against an in-scope target — the
    commodity pass (delegate what nuclei owns; see `scan_coverage`).

    `tags` takes plain intents (cve, exposure, misconfig, takeover, panel, tech, sqli,
    xss, ssrf, redirect, lfi, …) mapped to nuclei `-tags`; `templates` maps to `-t`;
    `severity` to `-severity` (e.g. 'critical,high'); `dast=True` enables nuclei
    fuzzing of discovered params; `record=True` files findings into the findings store.
    The result includes `also_run_native` — the probes nuclei can't do that you should
    run anyway. Requires nuclei installed. Intrusive: MOONMCP_ALLOW_INTRUSIVE +
    MOONMCP_ALLOW_EXTERNAL_TOOLS + the host in scope.
    """

    host = normalize_target(target)
    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{host}"
    args = nucleimod.build_args(url, tags=tags, templates=templates, severity=severity, dast=dast)
    result = await cli.run_tool(
        "nuclei", args, timeout=ctx.settings.external_timeout, allow=ctx.settings.allow_external_tools
    )
    if not result.available:
        return {
            "error": "nuclei_unavailable",
            "detail": result.error,
            "suggestion": "Install nuclei, or use analyze_headers + well_known + "
                          "content_discovery + cve_search for a native first pass.",
            "also_run_native": nucleimod.also_run_native(),
        }
    findings = [nucleimod.normalize_finding(r) for r in cli.parse_jsonl(result.stdout)]
    recorded = 0
    if record:
        for f in findings:
            ctx.findings.add(target=host, severity=f["severity"], title=f["name"],
                             type="nuclei", detail=f.get("description", ""),
                             evidence=f.get("matched_at", ""), source=f.get("template_id", ""))
            recorded += 1
    return {
        "target": url,
        "findings": findings,
        "finding_count": len(findings),
        "recorded": recorded,
        "also_run_native": nucleimod.also_run_native(),
        "note": ("nuclei is the commodity pass — now run the native-edge probes "
                 "(see scan_coverage) for bugs that survive the nuclei crowd"),
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "stderr_tail": result.stderr[-500:] if result.stderr else "",
    }


# ---------------------------------------------------------------------------
# resources & prompts
# ---------------------------------------------------------------------------
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
