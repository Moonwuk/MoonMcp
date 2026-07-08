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

import functools
import platform
import re
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .context import AppContext, build_context, to_dict
from .external import cli
from .intel import cve, shodan
from .net import dns as dnsmod
from .net import ports as portsmod
from .net import tls as tlsmod
from .recon import content as contentmod
from .recon import fingerprint as fpmod
from .recon import headers as headersmod
from .recon import subdomains as submod
from .recon import wayback as waybackmod
from .scope import ScopeError, normalize_target

_INSTRUCTIONS = """\
MoonMCP is a scope-aware bug-bounty & reconnaissance server.

Workflow: call `server_status` first, authorise targets with `scope_add`, then
use the recon tools. Every packet-sending tool refuses out-of-scope targets, so
add authorised assets before probing. Prefer the passive tools (subdomains,
wayback, cve_search, host_intel) and light active tools (dns_lookup, http_probe,
tls_inspect, analyze_headers, fingerprint, well_known) first; port_scan,
content_discovery and vuln_scan are intrusive and gated. `recon_target` runs a
safe passive+light sweep in one call. Only test systems you are authorised to test.
"""

mcp = FastMCP("moonmcp", instructions=_INSTRUCTIONS)
mcp._mcp_server.version = __version__

_CTX: AppContext | None = None


def get_context() -> AppContext:
    """Lazily build and cache the shared application context."""

    global _CTX
    if _CTX is None:
        _CTX = build_context()
    return _CTX


class ToolBlocked(Exception):
    """Raised when a tool is disabled by configuration (not a scope problem)."""


def safe_tool(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Wrap a tool so scope/validation failures return structured errors."""

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await func(*args, **kwargs)
        except ScopeError as exc:
            return {"error": "out_of_scope", "detail": str(exc),
                    "hint": "Add the target to scope with scope_add, or check scope_list."}
        except ToolBlocked as exc:
            return {"error": "disabled", "detail": str(exc)}
        except ValueError as exc:
            return {"error": "invalid_input", "detail": str(exc)}
    return wrapper


def _require_scope(target: str, *, intrusive: bool = False) -> str:
    ctx = get_context()
    if intrusive and not ctx.settings.allow_intrusive:
        raise ToolBlocked(
            "intrusive tools are disabled. Enable with MOONMCP_ALLOW_INTRUSIVE=1."
        )
    return ctx.scope.check(target)


def _scope_check() -> Callable[[str], bool]:
    """A predicate the HTTP client uses to refuse out-of-scope redirects."""

    ctx = get_context()
    return lambda url: ctx.scope.is_in_scope(url)


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    host = normalize_target(target)
    # normalize_target strips the port; recover it if the user supplied one.
    raw = target.strip()
    port = default_port
    if raw.startswith("["):  # [ipv6]:port
        end = raw.find("]")
        rest = raw[end + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif "://" in raw:
        from urllib.parse import urlsplit
        p = urlsplit(raw)
        try:
            parsed_port = p.port
        except ValueError:
            parsed_port = None  # out-of-range port in the URL; fall back to default
        if parsed_port:
            port = parsed_port
        elif p.scheme == "http":
            port = 80
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        port = int(raw.rsplit(":", 1)[1])
    return host, port


_HOSTISH_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,63}(?::\d+)?$", re.IGNORECASE)
# Final-label extensions that mean "this is a file/list arg", not a hostname,
# so we don't false-positive a wordlist/config path as a scan target.
_NON_TLD = {
    "txt", "json", "yaml", "yml", "xml", "csv", "html", "htm", "conf", "cfg",
    "ini", "log", "list", "md", "js", "py", "sh", "pdf", "png", "jpg", "toml",
}


def _host_like_tokens(args: list[str]) -> list[str]:
    """Extract host/URL/IP-looking tokens from a CLI arg list (for scope checks).

    Skips flags and non-target tokens (template paths, severities, wordlists) so
    that every actual scan target in ``args`` gets scope-checked.
    """

    import ipaddress

    found: list[str] = []
    for tok in args:
        t = tok.strip()
        if not t or t.startswith("-"):
            continue
        if "://" in t:
            found.append(t)
            continue
        if "/" in t or "," in t or " " in t:
            continue  # path / list / not a bare host
        try:
            ipaddress.ip_address(t.split(":", 1)[0])
            found.append(t)
            continue
        except ValueError:
            pass
        host_only = t.split(":", 1)[0]
        if _HOSTISH_RE.match(t) and host_only.rsplit(".", 1)[-1].lower() not in _NON_TLD:
            found.append(t)
    return found


# ---------------------------------------------------------------------------
# meta / scope
# ---------------------------------------------------------------------------
@mcp.tool()
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
        "name": "MoonMCP",
        "version": __version__,
        "python": platform.python_version(),
        "scope": ctx.scope.entries(),
        "scope_enforced": s.enforce_scope,
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


@mcp.tool()
async def scope_list() -> dict:
    """List the current in-scope and out-of-scope entries."""

    ctx = get_context()
    return {"enforced": ctx.scope.enforce, "empty": ctx.scope.is_empty, **ctx.scope.entries()}


@mcp.tool()
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
async def scope_exclude(target: str) -> dict:
    """Mark a target as out-of-scope. Exclusions always override the allowlist."""

    ctx = get_context()
    excluded = ctx.scope.exclude(target)
    return {"excluded": excluded, "scope": ctx.scope.entries()}


@mcp.tool()
async def scope_remove(target: str) -> dict:
    """Remove a previously added scope entry (from allow or deny lists)."""

    ctx = get_context()
    removed = ctx.scope.remove(target)
    return {"removed": removed, "scope": ctx.scope.entries()}


# ---------------------------------------------------------------------------
# passive OSINT
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def enumerate_subdomains(domain: str, sources: list[str] | None = None) -> dict:
    """Passively enumerate subdomains of a domain via free OSINT sources.

    Queries certificate transparency (crt.sh), HackerTarget, AnubisDB and
    AlienVault OTX in parallel and merges the results. Passive — no packets are
    sent to the target itself. ``sources`` optionally restricts which providers
    to use (see server_status / available list: crtsh, hackertarget, anubis, otx).
    """

    host = _require_scope(domain)
    ctx = get_context()
    result = await submod.enumerate_subdomains(ctx.http, host, sources=sources)
    data = to_dict(result)
    data["count"] = result.count  # @property is not picked up by to_dict
    return data


@mcp.tool()
@safe_tool
async def wayback_urls(domain: str, limit: int = 500, include_subdomains: bool = True) -> dict:
    """Fetch historical URLs for a domain from the Internet Archive (Wayback).

    Passive. Surfaces old endpoints, parameters and forgotten files. Flags
    'interesting' URLs (backups, configs, .git, api, tokens, ...) separately.
    """

    host = _require_scope(domain)
    ctx = get_context()
    result = await waybackmod.fetch_wayback_urls(
        ctx.http, host, limit=limit, include_subdomains=include_subdomains
    )
    return to_dict(result)


@mcp.tool()
@safe_tool
async def cve_lookup(cve_id: str) -> dict:
    """Look up a single CVE by ID (e.g. CVE-2021-44228) from the NVD database.

    Returns description, CVSS score/severity/vector, CWE mappings and references.
    """

    ctx = get_context()
    record = await cve.lookup_cve(ctx.http, cve_id, api_key=ctx.settings.nvd_api_key)
    if record is None:
        return {"error": "not_found", "detail": f"No NVD record for {cve_id}"}
    return to_dict(record)


@mcp.tool()
@safe_tool
async def cve_search(keyword: str, limit: int = 15) -> dict:
    """Keyword-search the NVD for CVEs (e.g. 'apache log4j 2.14').

    Results are sorted most-severe first by CVSS base score. Use this to map a
    fingerprinted product/version to known vulnerabilities.
    """

    ctx = get_context()
    result = await cve.search_cves(ctx.http, keyword, limit=limit, api_key=ctx.settings.nvd_api_key)
    return to_dict(result)


@mcp.tool()
@safe_tool
async def host_intel(ip: str) -> dict:
    """Look up an IP's exposure via Shodan.

    Uses Shodan's free InternetDB by default (open ports, hostnames, CPEs, known
    CVEs, tags); uses the full Shodan API automatically if a key is configured.
    Passive — queries Shodan, not the target.
    """

    ctx = get_context()
    result = await shodan.host_intel(ctx.http, ip.strip(), api_key=ctx.settings.shodan_api_key)
    return to_dict(result)


# ---------------------------------------------------------------------------
# active (light) — scope-gated
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def dns_lookup(target: str) -> dict:
    """Resolve a host's DNS records (A/AAAA, plus MX/NS/TXT/CNAME/SOA/CAA when
    dnspython is installed) and attempt a reverse PTR lookup on its A records.
    Requires the target to be in scope.
    """

    host = _require_scope(target)
    result = await dnsmod.resolve(host)
    data = to_dict(result)
    ptr = {}
    for ip in (result.a or [])[:3]:
        names = await dnsmod.reverse_lookup(ip)
        if names:
            ptr[ip] = names
    if ptr:
        data["ptr"] = ptr
    return data


@mcp.tool()
@safe_tool
async def http_probe(
    target: str,
    method: str = "GET",
    follow_redirects: bool = True,
    verify_tls: bool = True,
) -> dict:
    """Send a single HTTP(S) request to an in-scope target and return a structured
    result: status, reason, response headers, timing, the full redirect chain,
    page title and body size. Accepts a bare host (defaults to https) or a full
    URL. The primary building block for web recon.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    host = _require_scope(url)
    ctx = get_context()
    result = await ctx.http.fetch(
        url,
        method=method,
        follow_redirects=follow_redirects,
        verify_tls=verify_tls,
        max_redirects=ctx.settings.max_redirects,
        scope_check=_scope_check(),
    )
    out = {
        "requested_url": url,
        "host": host,
        "status": result.status,
        "reason": result.reason,
        "final_url": result.final_url,
        "redirect_chain": result.redirect_chain,
        "elapsed_ms": result.elapsed_ms,
        "headers": result.headers_map(),
        "body_bytes": len(result.body),
        "truncated": result.truncated,
    }
    set_cookies = result.get_all("set-cookie")
    if len(set_cookies) > 1:
        out["set_cookie"] = set_cookies
    if result.error:
        out["error"] = result.error
    if result.redirect_blocked:
        out["redirect_blocked"] = result.redirect_blocked
    fp = fpmod.fingerprint(result)
    if fp.title:
        out["title"] = fp.title
    return out


@mcp.tool()
@safe_tool
async def tls_inspect(target: str, port: int = 443) -> dict:
    """Inspect a host's TLS certificate: subject, issuer, validity window, days
    until expiry, negotiated protocol/cipher, and — most useful for recon — the
    Subject Alternative Names, which often reveal sibling hostnames. In scope only.
    """

    host, tls_port = _split_host_port(target, port)
    _require_scope(host)
    result = await tlsmod.inspect_certificate(host, tls_port, timeout=get_context().settings.timeout)
    return to_dict(result)


@mcp.tool()
@safe_tool
async def analyze_headers(target: str) -> dict:
    """Fetch a URL and audit its HTTP security headers.

    Grades (A-F) the presence of HSTS, CSP, X-Frame-Options, X-Content-Type-
    Options, Referrer-Policy and Permissions-Policy; flags information-leaking
    headers (Server, X-Powered-By, ...) and risky Set-Cookie flags. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    result = await ctx.http.fetch(
        url, follow_redirects=True, max_redirects=ctx.settings.max_redirects, scope_check=_scope_check()
    )
    if result.status is None:
        return {"error": "unreachable", "detail": result.error, "url": url}
    audit = headersmod.audit_headers(result)
    return to_dict(audit)


@mcp.tool()
@safe_tool
async def fingerprint(target: str) -> dict:
    """Fetch a URL and fingerprint its technology stack: web server, CDN/WAF,
    language/runtime, frameworks, CMS and front-end libraries, with version hints
    and the evidence for each match. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    host = _require_scope(url)
    ctx = get_context()
    result = await ctx.http.fetch(
        url, follow_redirects=True, max_redirects=ctx.settings.max_redirects, scope_check=_scope_check()
    )
    if result.status is None:
        return {"error": "unreachable", "detail": result.error, "url": url}
    dns_res = await dnsmod.resolve(host)
    ip = (dns_res.a or [None])[0]
    fp = fpmod.fingerprint(result, ip=ip)
    return to_dict(fp)


@mcp.tool()
@safe_tool
async def well_known(target: str) -> dict:
    """Fetch and parse a host's disclosure files: robots.txt (extracting the
    referenced paths), sitemap.xml (extracting <loc> URLs), security.txt and
    humans.txt. A quick, low-noise way to discover structure. In scope only.
    """

    host, port = _split_host_port(target, 443)
    _require_scope(host)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    ctx = get_context()
    result = await contentmod.fetch_well_known(
        ctx.http, host, scheme=scheme, port=port, scope_check=_scope_check()
    )
    return to_dict(result)


# ---------------------------------------------------------------------------
# active (intrusive) — scope-gated + allow_intrusive
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
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

    host = _require_scope(target, intrusive=True)
    port_list = portsmod.parse_ports(ports)
    if len(port_list) > 5000:
        return {"error": "too_many_ports", "detail": f"{len(port_list)} ports requested; cap is 5000"}
    ctx = get_context()
    result = await portsmod.scan_ports(
        host,
        port_list,
        timeout=timeout,
        concurrency=min(200, ctx.settings.max_concurrency * 10),
        grab_banner=grab_banner,
        limiter=ctx.governor.limiter,
    )
    return to_dict(result)


@mcp.tool()
@safe_tool
async def content_discovery(
    target: str,
    wordlist: list[str] | None = None,
    concurrency: int = 15,
) -> dict:
    """Probe an in-scope host for common sensitive paths (admin panels, API docs,
    .git/.env, backups, config files, ...) using a compact built-in wordlist or a
    caller-supplied one. Reports each path's status, size and content type.
    Intrusive: requires MOONMCP_ALLOW_INTRUSIVE and the host to be in scope.
    """

    host, port = _split_host_port(target, 443)
    _require_scope(host, intrusive=True)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    ctx = get_context()
    result = await contentmod.probe_paths(
        ctx.http, host, scheme=scheme, port=port, wordlist=wordlist,
        concurrency=min(concurrency, ctx.settings.max_concurrency),
    )
    return to_dict(result)


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def recon_target(domain: str, include_subdomains: bool = True) -> dict:
    """One-shot passive+light recon of an in-scope domain.

    Chains the safe tools into a single report: subdomain enumeration, DNS
    resolution, TLS certificate (with SANs), an HTTP probe, security-header
    grade, and a technology fingerprint of the apex. No intrusive scanning is
    performed. Ideal as the first call against a new target.
    """

    host = _require_scope(domain)
    ctx = get_context()
    report: dict[str, Any] = {"target": host}

    if include_subdomains:
        subs = await submod.enumerate_subdomains(ctx.http, host)
        report["subdomains"] = {"count": subs.count, "sources": subs.sources,
                                "sample": subs.subdomains[:50]}

    dns_res = await dnsmod.resolve(host)
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

    tls_res = await tlsmod.inspect_certificate(host, 443, timeout=ctx.settings.timeout)
    if tls_res.connected:
        report["tls"] = {
            "issuer": tls_res.issuer.get("organizationName") or tls_res.issuer,
            "not_after": tls_res.not_after,
            "days_until_expiry": tls_res.days_until_expiry,
            "subject_alt_names": tls_res.subject_alt_names,
        }
    return report


# ---------------------------------------------------------------------------
# external CLI integration
# ---------------------------------------------------------------------------
@mcp.tool()
async def external_tools() -> dict:
    """List the external security CLIs MoonMCP knows about and whether each is
    installed on PATH, plus the native MoonMCP fallback for each. Use before
    calling run_scanner or vuln_scan to know what is available.
    """

    return {"tools": cli.detect_tools(), "runner_enabled": get_context().settings.allow_external_tools}


@mcp.tool()
@safe_tool
async def run_scanner(tool: str, args: list[str], target: str | None = None) -> dict:
    """Run an installed external security CLI and return its output.

    ``tool`` must be one of the known tools (subfinder, httpx, nuclei, naabu,
    nmap, katana, ffuf, gau, dnsx, amass, waybackurls). ``args`` are passed
    through verbatim. If ``target`` is given it is scope-checked first. If the
    tool is missing, returns a structured note and the native fallback to use
    instead. JSONL output is auto-parsed. Gated by MOONMCP_ALLOW_EXTERNAL_TOOLS.
    """

    ctx = get_context()
    if tool not in cli.KNOWN_TOOLS:
        return {"error": "unknown_tool", "detail": f"{tool} is not a known scanner",
                "known": list(cli.KNOWN_TOOLS)}
    # Scope-check the declared target AND every host/URL/IP in args — the real
    # scan target usually lives inside args (e.g. `-u https://host`).
    to_check = ([target] if target else []) + _host_like_tokens(args)
    if ctx.settings.enforce_scope and not to_check:
        return {"error": "no_target",
                "detail": "Refusing to run a scanner with no scope-checked target while "
                          "enforcement is on. Pass a 'target' that is in scope, or include the "
                          "host/URL in args."}
    for t in to_check:
        _require_scope(t)
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
async def vuln_scan(target: str, templates: str | None = None, severity: str | None = None) -> dict:
    """Run a nuclei template-based vulnerability scan against an in-scope target.

    Requires nuclei to be installed (there is no safe stdlib equivalent for
    template-based scanning). ``templates`` maps to nuclei ``-t`` and ``severity``
    to ``-severity`` (e.g. 'critical,high'). Intrusive: requires
    MOONMCP_ALLOW_INTRUSIVE, MOONMCP_ALLOW_EXTERNAL_TOOLS and the host in scope.
    """

    host = _require_scope(target, intrusive=True)
    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{host}"
    args = ["-u", url, "-jsonl", "-silent", "-duc"]
    if templates:
        args += ["-t", templates]
    if severity:
        args += ["-severity", severity]
    result = await cli.run_tool(
        "nuclei", args, timeout=ctx.settings.external_timeout, allow=ctx.settings.allow_external_tools
    )
    if not result.available:
        return {
            "error": "nuclei_unavailable",
            "detail": result.error,
            "suggestion": "Install nuclei, or use analyze_headers + well_known + "
                          "content_discovery + cve_search for a native first pass.",
        }
    findings = cli.parse_jsonl(result.stdout)
    return {
        "target": url,
        "findings": findings,
        "finding_count": len(findings),
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


def run() -> None:
    """Entry point: serve over stdio.

    The application context (and its asyncio primitives) is built lazily on the
    first tool call, i.e. inside the running event loop.
    """

    mcp.run()


if __name__ == "__main__":
    run()
