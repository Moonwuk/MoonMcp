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
from . import prompts as promptmod
from .context import AppContext, build_context, to_dict
from .external import cli
from .intel import asn as asnmod
from .intel import cve, shodan
from .intel import email as emailmod
from .knowledge import injections as injmod
from .knowledge import privesc as privescmod
from .knowledge import techniques as techmod
from .knowledge import vulns as vulnsmod
from .knowledge import waf_kb as wafkbmod
from .net import dns as dnsmod
from .net import jarm as jarmmod
from .net import ports as portsmod
from .net import tls as tlsmod
from .recon import binary as binarymod
from .recon import config_audit as configmod
from .recon import content as contentmod
from .recon import crawl as crawlmod
from .recon import favicon as faviconmod
from .recon import fingerprint as fpmod
from .recon import headers as headersmod
from .recon import origin as originmod
from .recon import secrets as secretsmod
from .recon import subdomains as submod
from .recon import wayback as waybackmod
from .reporting import format_markdown
from .scope import ScopeError, normalize_target
from .web import behavior as behaviormod
from .web import cors as corsmod
from .web import desync as desyncmod
from .web import exposure as exposuremod
from .web import graphql as graphqlmod
from .web import jwt as jwtmod
from .web import methods as methodsmod
from .web import redirect as redirectmod
from .web import screenshot as screenshotmod
from .web import takeover as takeovermod
from .web import waf as wafmod
from .web import waf_bypass as wafbypassmod

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
        except Exception as exc:  # never surface an opaque crash to the MCP client
            return {"error": "internal_error", "detail": f"{type(exc).__name__}: {exc}"}
    return wrapper


def _require_scope(target: str, *, intrusive: bool = False) -> str:
    ctx = get_context()
    if intrusive and not ctx.settings.allow_intrusive:
        raise ToolBlocked(
            "intrusive tools are disabled. Enable with MOONMCP_ALLOW_INTRUSIVE=1."
        )
    host = ctx.scope.check(target)
    # Resolve-then-check SSRF guard — covers raw-socket tools (port_scan,
    # tls_inspect, jarm, desync) as well as an in-scope hostname that points at a
    # private/internal/cloud-metadata IP. No-op when block_private is disabled.
    reason = ctx.scope.blocked_connect_reason(target)
    if reason is not None:
        raise ScopeError(reason)
    return host


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
        "name": "MoonMCP",
        "version": __version__,
        "python": platform.python_version(),
        "scope": ctx.scope.entries(),
        "scope_enforced": s.enforce_scope,
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


@mcp.tool()
@safe_tool
async def ip_intel(ip: str) -> dict:
    """Map an IP to its infrastructure: ASN, organisation, ISP, cloud/CDN provider
    (AWS/GCP/Azure/Cloudflare/…), hosting flag, reverse DNS and geo. Passive —
    queries a public dataset, not the target. Useful for spotting whether a host
    sits behind a CDN and which provider owns the range.
    """

    ctx = get_context()
    result = await asnmod.ip_intel(ctx.http, ip)
    return to_dict(result)


@mcp.tool()
@safe_tool
async def reverse_ip(ip: str) -> dict:
    """List other domains co-hosted on the same IP (reverse-IP lookup). Passive
    third-party dataset. Good for widening the attack surface and spotting shared
    hosting (note: shared IPs on big CDNs return many unrelated domains).
    """

    ctx = get_context()
    result = await asnmod.reverse_ip(ctx.http, ip)
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
    result = await dnsmod.resolve(host, http_client=get_context().http)
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
    dns_res = await dnsmod.resolve(host, http_client=ctx.http)
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
# web-app checks (light active, scope-gated) + email OSINT
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def crawl(target: str, max_pages: int = 10) -> dict:
    """Lightly crawl an in-scope site (depth 1, bounded) and extract its attack
    surface: internal links, forms + their input names, JavaScript/asset URLs,
    query parameters, external hosts it reaches, and any emails. HTML parsing
    only — no browser. In scope only; redirects that leave scope are not followed.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    result = await crawlmod.crawl(
        ctx.http, url, scope_check=_scope_check(), max_pages=max(1, min(max_pages, 30))
    )
    return to_dict(result)


@mcp.tool()
@safe_tool
async def extract_secrets(target: str, scan_js: bool = True, max_js: int = 15) -> dict:
    """Fetch an in-scope page (and, by default, its linked JavaScript) and scan
    for exposed secrets: cloud keys (AWS/GCP), API tokens (GitHub, Slack, Stripe,
    Twilio, SendGrid, ...), private keys, JWTs and risky credential assignments.
    Uses high-precision, prefix-anchored patterns; findings are redacted. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    scan = await secretsmod.scan_secrets(
        ctx.http, url, scope_check=_scope_check(), include_js=scan_js,
        max_js=max(1, min(max_js, 40)),
    )
    data = to_dict(scan)
    data["count"] = scan.count
    return data


@mcp.tool()
@safe_tool
async def cors_audit(target: str) -> dict:
    """Test an in-scope URL for CORS misconfigurations: arbitrary-origin
    reflection, 'null' origin acceptance, and prefix/suffix/subdomain bypasses —
    flagged more severely when Access-Control-Allow-Credentials is also true.
    Sends benign GETs with crafted Origin headers. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    result = await corsmod.audit_cors(ctx.http, url)
    return to_dict(result)


@mcp.tool()
@safe_tool
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
    _require_scope(url)
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
@safe_tool
async def graphql_check(target: str) -> dict:
    """Probe an in-scope host for GraphQL endpoints across common paths and test
    whether schema introspection is enabled (which leaks the full API surface).
    In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    result = await graphqlmod.discover_graphql(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@safe_tool
async def waf_detect(target: str) -> dict:
    """Fingerprint an in-scope host's WAF/CDN from response headers, cookies and
    server strings (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, F5, ...). When
    intrusive mode is on, it also sends benign suspicious requests to see whether
    a protective layer trips. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    result = await wafmod.detect_waf(
        ctx.http, url, scope_check=_scope_check(), active=ctx.settings.allow_intrusive
    )
    return to_dict(result)


@mcp.tool()
@safe_tool
async def takeover_check(target: str) -> dict:
    """Check an in-scope subdomain for a potential subdomain takeover: resolves
    the CNAME chain, matches it against a database of takeover-prone providers
    (S3, GitHub Pages, Heroku, Shopify, Azure, ...), and looks for the provider's
    'unclaimed resource' fingerprint (or a dangling DNS record). Results are
    triage signals — verify manually. In scope only.
    """

    host = _require_scope(target)
    ctx = get_context()
    result = await takeovermod.check_takeover(ctx.http, host, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@safe_tool
async def open_redirect(target: str) -> dict:
    """Test an in-scope URL for open-redirect flaws by injecting an external
    canary into the common redirect parameters (url, next, redirect, returnTo, …)
    and checking whether the server bounces to it via a Location header,
    meta-refresh or JS redirect. Redirects are not followed (the canary is never
    contacted). In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    result = await redirectmod.check_open_redirect(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@safe_tool
async def vcs_exposure(target: str) -> dict:
    """Check an in-scope host for exposed VCS/config artefacts (.git, .svn, .hg,
    .env, .DS_Store). Confirms real exposure by validating each file's content
    signature (not just a 200), extracts the git remote URL and recent commit
    log when a .git is exposed. Source disclosure via an exposed .git is
    high-impact. In scope only.
    """

    host, port = _split_host_port(target, 443)
    _require_scope(host)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    base = raw if "://" in raw else f"{scheme}://{host}"
    ctx = get_context()
    result = await exposuremod.check_exposure(ctx.http, base, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@safe_tool
async def screenshot(target: str, full_page: bool = True, return_base64: bool = False) -> dict:
    """Capture a rendered screenshot of an in-scope page using Playwright +
    Chromium, saved to disk (path returned). Optional and self-degrading: if
    Playwright/Chromium isn't installed, returns a clear note with an install
    hint instead of erroring. Set return_base64 to also inline the PNG. In scope only.
    """

    import tempfile

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    out_dir = ctx.settings.screenshot_dir or __import__("os").path.join(
        tempfile.gettempdir(), "moonmcp-screenshots"
    )
    result = await screenshotmod.capture(
        url, out_dir=out_dir, full_page=full_page, return_base64=return_base64,
        timeout_ms=int(ctx.settings.timeout * 2000),
    )
    return to_dict(result)


@mcp.tool()
@safe_tool
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
    _require_scope(url)
    ctx = get_context()
    fetched = await ctx.http.fetch(url, follow_redirects=True, timeout=30.0,
                                   max_body=12 * 1024 * 1024, scope_check=_scope_check())
    if fetched.status is None:
        return {"error": "unreachable", "detail": fetched.error, "url": url}
    if not fetched.body:
        return {"error": "empty_body", "detail": f"HTTP {fetched.status}", "url": url}

    analysis = binarymod.analyze_bytes(fetched.body, url=fetched.final_url or url)
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
@safe_tool
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
        _require_scope(url)
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
async def email_security(domain: str) -> dict:
    """Analyze a domain's email-spoofing posture over DNS: SPF, DMARC (policy),
    DKIM (common selectors) and CAA, with an A-F grade and specific weaknesses
    (missing/again weak SPF, DMARC p=none, no CAA, ...). Passive DNS. In scope only.
    """

    host = _require_scope(domain)
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
async def favicon_hash(target: str) -> dict:
    """Compute an in-scope site's favicon hash (Shodan-style mmh3). Two hosts
    sharing a favicon hash are usually the same product/instance, so the returned
    `http.favicon.hash:<hash>` query lets you pivot on Shodan/Censys/FOFA to find
    sibling assets — including origin servers hiding behind a CDN. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    result = await faviconmod.fetch_favicon_hash(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@safe_tool
async def tls_fingerprint(target: str, port: int = 443) -> dict:
    """Profile a host's TLS configuration: which protocol versions it supports
    (flagging weak TLS 1.0/1.1), the cipher per version, and ALPN / HTTP-2
    support. A compact server-side TLS fingerprint for infra mapping and posture.
    In scope only.
    """

    host, tls_port = _split_host_port(target, port)
    _require_scope(host)
    result = await tlsmod.probe_tls_profile(host, tls_port, timeout=get_context().settings.timeout)
    return to_dict(result)


@mcp.tool()
@safe_tool
async def jarm_fingerprint(target: str, port: int = 443) -> dict:
    """Compute the **JARM** active TLS fingerprint of an in-scope host (Salesforce's
    62-char server fingerprint from 10 crafted TLS handshakes). Two servers with
    the same JARM are configured identically at the TLS layer — a strong pivot for
    finding sibling infrastructure / origin servers and for matching known stacks
    (or C2) in public JARM databases. In scope only.
    """

    host, jport = _split_host_port(target, port)
    _require_scope(host)
    ctx = get_context()
    result = await jarmmod.compute_jarm(host, jport, timeout=max(10.0, ctx.settings.timeout))
    return to_dict(result)


@mcp.tool()
@safe_tool
async def origin_discovery(domain: str) -> dict:
    """Try to find the real origin IP behind a CDN/WAF for an in-scope host.
    Resolves the front IPs and detects the CDN, then hunts candidate origins via
    certificate SANs, common non-proxied subdomains (origin/direct/mail/cpanel/…)
    and MX records, flagging IPs that sit on *different* infrastructure than the
    CDN front. Passive+light. In scope only.
    """

    host = _require_scope(domain)
    ctx = get_context()
    result = await originmod.discover_origin(ctx.http, host, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@safe_tool
async def behavior_probe(target: str) -> dict:
    """Profile how an in-scope target *behaves*: 404 handling (soft-404 / custom),
    stack-trace / error disclosure, Host and X-Forwarded-Host reflection
    (cache-poisoning / host-header-injection hints), advertised methods and
    response time. Light, benign requests only. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url)
    ctx = get_context()
    result = await behaviormod.profile_behavior(ctx.http, url, scope_check=_scope_check())
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


@mcp.tool()
@safe_tool
async def http_methods(target: str) -> dict:
    """Enumerate an in-scope URL's allowed HTTP methods (from OPTIONS) and probe
    sensitive ones (TRACE, PUT, DELETE, PATCH) to flag XST or write-enabled
    endpoints. Intrusive (it sends potentially state-changing methods): requires
    MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    _require_scope(url, intrusive=True)
    ctx = get_context()
    result = await methodsmod.check_methods(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@safe_tool
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
    _require_scope(url, intrusive=True)
    ctx = get_context()
    result = await wafbypassmod.test_waf_efficacy(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@safe_tool
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
    _require_scope(url, intrusive=True)
    result = await desyncmod.probe_desync(url, timeout=max(10.0, get_context().settings.timeout))
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
    f = ctx.findings.add(target=target.strip().lower(), severity=severity, title=title,
                         detail=detail, evidence=evidence, type=type, source="manual",
                         created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    return {"recorded": to_dict(f), "summary": ctx.findings.summary()}


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


# ---------------------------------------------------------------------------
# knowledge base — injections (patterns, causes, signatures)
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def injection_info(injection_class: str | None = None) -> dict:
    """Look up MoonMCP's injection knowledge base: patterns (detection payloads),
    causes (root causes) and signatures (exact error strings / regexes to detect
    the vuln from a response). Pass an injection class id/alias (e.g. sqli, xss,
    ssti, cmdi, xxe, ssrf, crlf, path-traversal, ldap, xpath, nosqli, ssi,
    graphql, prompt-injection) for full detail, or omit for the index + stats.
    No network — pure reference.
    """

    if not injection_class:
        return {"stats": injmod.stats(), "classes": injmod.list_classes()}
    entry = injmod.get_class(injection_class)
    if entry is None:
        return {"error": "unknown_class", "detail": f"No injection class '{injection_class}'",
                "known": [c["id"] for c in injmod.list_classes()]}
    return entry


@mcp.tool()
@safe_tool
async def injection_search(query: str) -> dict:
    """Search the injection knowledge base by keyword (name, alias, CWE, summary)."""

    return {"query": query, "results": injmod.search(query)}


@mcp.tool()
@safe_tool
async def match_injection_signatures(text: str, injection_class: str | None = None) -> dict:
    """Scan a blob of text (e.g. an HTTP response body from http_probe) for known
    injection error/regex signatures and report which injection class + technology
    each match indicates — a fast way to spot a likely SQLi/SSTI/etc. from a raw
    error message. Optionally restrict to one class. No network.
    """

    matches = injmod.match_signatures(text, class_id=injection_class)
    return {"match_count": len(matches), "matches": matches}


@mcp.tool()
@safe_tool
async def technique_info(technique: str | None = None, category: str | None = None,
                         language: str | None = None) -> dict:
    """Look up MoonMCP's techniques & notable-PoC catalog — a referenced index of
    exploitation techniques and landmark public vulnerabilities across languages
    (web, deserialization, memory-corruption/asm, famous CVEs, language-specific,
    kernel/low-level). Pass a technique id or CVE for full detail; or filter by
    `category` / `language`; or omit for the index + stats. Each entry links to
    the public PoC/research — it is a knowledge reference, not exploit code.
    """

    if technique:
        entry = techmod.get_technique(technique)
        if entry is None:
            return {"error": "unknown_technique", "detail": f"No technique '{technique}'",
                    "categories": techmod.categories()}
        return entry
    if category:
        return {"category": category, "results": techmod.by_category(category)}
    if language:
        return {"language": language, "results": techmod.by_language(language)}
    return {"stats": techmod.stats(), "techniques": techmod.list_techniques()}


@mcp.tool()
@safe_tool
async def technique_search(query: str) -> dict:
    """Search the techniques & PoC catalog by keyword, language, CVE or category."""

    return {"query": query, "results": techmod.search(query)}


# ---------------------------------------------------------------------------
# knowledge base — privilege escalation (techniques + tooling)
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def privesc_info(technique: str | None = None, platform: str | None = None,
                       category: str | None = None) -> dict:
    """Look up MoonMCP's privilege-escalation knowledge base — a referenced catalog
    of local privesc techniques across Linux, Windows, container, cloud and Active
    Directory, with benign enumeration commands, detection indicators and links to
    public research (no exploit code). Pass a technique id or CVE for full detail;
    or filter by `platform` (linux/windows/container/cloud/active-directory) or
    `category` (sudo, suid-sgid, capabilities, kernel-exploit, service-misconfig,
    token-impersonation, container-escape, cloud-iam, kerberos, adcs, …); or omit
    for the index + stats. No network — pure reference.
    """

    if technique:
        entry = privescmod.get_technique(technique)
        if entry is None:
            return {"error": "unknown_technique", "detail": f"No privesc technique '{technique}'",
                    "platforms": privescmod.platforms(), "categories": privescmod.categories()}
        return entry
    if platform:
        return {"platform": platform, "results": privescmod.by_platform(platform)}
    if category:
        return {"category": category, "results": privescmod.by_category(category)}
    return {"stats": privescmod.stats(), "techniques": privescmod.list_techniques()}


@mcp.tool()
@safe_tool
async def privesc_search(query: str) -> dict:
    """Search the privilege-escalation KB by keyword (name, platform, category, CVE,
    tool or detection indicator).
    """

    return {"query": query, "results": privescmod.search(query)}


@mcp.tool()
@safe_tool
async def privesc_tools(tool: str | None = None, query: str | None = None) -> dict:
    """Catalog of privilege-escalation TOOLING (LinPEAS/WinPEAS, GTFOBins, LOLBAS,
    PowerUp, Seatbelt, pspy, linux-exploit-suggester, the potato family, BloodHound,
    …). Pass a `tool` id/name for detail, a `query` to search, or omit for the full
    list. No network — pure reference.
    """

    if tool:
        entry = privescmod.get_tool(tool)
        if entry is None:
            return {"error": "unknown_tool", "detail": f"No privesc tool '{tool}'",
                    "known": [t["id"] for t in privescmod.list_tools()]}
        return entry
    if query:
        return {"query": query, "results": privescmod.search_tools(query)}
    return {"count": len(privescmod.list_tools()), "tools": privescmod.list_tools()}


@mcp.tool()
@safe_tool
async def match_privesc(text: str, platform: str | None = None) -> dict:
    """Scan pasted local-enumeration output (e.g. `sudo -l`, `id`, a SUID listing,
    `getcap -r /`, `whoami /priv`, `systeminfo`) for known privilege-escalation
    vectors and report which techniques the output indicates — a fast triage of a
    foothold's escalation paths. Optionally restrict to one `platform`. No network.
    """

    matches = privescmod.match_enumeration(text, platform=platform)
    return {"match_count": len(matches), "matches": matches}


# ---------------------------------------------------------------------------
# knowledge base — server-side vulnerabilities + root-cause taxonomy
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def vuln_info(vuln: str | None = None, category: str | None = None,
                    popularity: str | None = None, root_cause: str | None = None) -> dict:
    """Look up MoonMCP's server-side vulnerability catalog — popular AND obscure
    classes (SSRF, SQLi, RCE, deserialization, request smuggling, SSTI, XXE,
    cache poisoning, mass assignment, prototype pollution, race conditions,
    GraphQL/NoSQL/LDAP/XPath, header injection, …). Each entry maps to its ROOT
    CAUSE and the concrete point where real apps break (`where_it_breaks`), with
    detection, WAF notes and notable real-world incidents. Pass a `vuln` id for
    detail; filter by `category`, `popularity` (common/uncommon/rare) or
    `root_cause`; or omit for the index + stats. No network — pure reference.
    """

    if vuln:
        entry = vulnsmod.get_vuln(vuln)
        if entry is None:
            return {"error": "unknown_vuln", "detail": f"No vulnerability '{vuln}'",
                    "categories": vulnsmod.categories()}
        return entry
    if category:
        return {"category": category, "results": vulnsmod.by_category(category)}
    if popularity:
        return {"popularity": popularity, "results": vulnsmod.by_popularity(popularity)}
    if root_cause:
        return {"root_cause": root_cause, "results": vulnsmod.by_root_cause(root_cause)}
    return {"stats": vulnsmod.stats(), "vulns": vulnsmod.list_vulns()}


@mcp.tool()
@safe_tool
async def vuln_search(query: str) -> dict:
    """Search the server-side vulnerability catalog by keyword (name, category,
    root cause, real-world incident, tool).
    """

    return {"query": query, "results": vulnsmod.search(query)}


@mcp.tool()
@safe_tool
async def rootcause_info(root_cause: str | None = None) -> dict:
    """The ROOT-CAUSE TAXONOMY — the ~13 fundamental causes from which nearly all
    server-side vulnerabilities spring (code/data confusion, confused-deputy /
    trust-boundary violation, parser differential, broken authorization, insecure
    deserialization, state desync/race, insecure defaults, memory safety, crypto
    misuse, network-position abuse, supply-chain trust, implicit trust of client
    metadata, ambient authority). Pass a `root_cause` id for its full write-up —
    why it recurs, the systemic fix, and every catalog vuln that derives from it;
    omit for the list. No network — the conceptual centrepiece of the KB.
    """

    if root_cause:
        entry = vulnsmod.get_root_cause(root_cause)
        if entry is None:
            return {"error": "unknown_root_cause", "detail": f"No root cause '{root_cause}'",
                    "known": [r["id"] for r in vulnsmod.list_root_causes()]}
        return entry
    return {"root_causes": vulnsmod.list_root_causes()}


@mcp.tool()
@safe_tool
async def vuln_tools(tool: str | None = None, query: str | None = None) -> dict:
    """Catalog of server-side vulnerability tooling (sqlmap, ghauri, commix,
    tplmap/SSTImap, ysoserial, jwt_tool, XXEinjector, Gopherus, interactsh/OAST,
    Arjun/x8 param discovery, ffuf/feroxbuster, smuggler/Turbo Intruder, dalfox,
    GraphQLmap, wafw00f, …). Pass a `tool` id/name, a `query`, or omit for all.
    No network — pure reference.
    """

    if tool:
        entry = vulnsmod.get_tool(tool)
        if entry is None:
            return {"error": "unknown_tool", "detail": f"No tool '{tool}'",
                    "known": [t["id"] for t in vulnsmod.list_tools()]}
        return entry
    if query:
        return {"query": query, "results": vulnsmod.search_tools(query)}
    return {"count": len(vulnsmod.list_tools()), "tools": vulnsmod.list_tools()}


# ---------------------------------------------------------------------------
# knowledge base — WAF (how they work · fingerprints · bypass concepts)
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def waf_info(waf: str | None = None, category: str | None = None) -> dict:
    """WAF reference KB: how WAFs work (rule engines, models, cloud WAFs), vendor
    fingerprints, and conceptual/defensive bypass techniques (understanding
    evasion to detect & defend — normalization & parser differentials, encoding
    layers, HPP, origin-IP discovery, …). Pass a `waf` entry id for detail;
    filter by `category` (how-it-works / fingerprint / bypass-technique); or omit
    for the index + stats. Complements the active waf_detect tool. No network.
    """

    if waf:
        entry = wafkbmod.get_entry(waf)
        if entry is None:
            return {"error": "unknown_entry", "detail": f"No WAF entry '{waf}'"}
        return entry
    if category:
        return {"category": category, "results": wafkbmod.list_entries(category)}
    return {"stats": wafkbmod.stats(), "entries": wafkbmod.list_entries()}


@mcp.tool()
@safe_tool
async def identify_waf(text: str) -> dict:
    """Identify the WAF in front of a target from a raw HTTP response (paste the
    headers + body / blocking page). Scans the fingerprint indicators (cf-ray,
    __cfduid, x-akamai, incap_ses, awselb, BigIP, x-sucuri, …) and names the
    vendor. No network — pass it output from http_probe.
    """

    matches = wafkbmod.identify(text)
    return {"match_count": len(matches), "matches": matches}


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

    tls_res = await tlsmod.inspect_certificate(host, 443, timeout=ctx.settings.timeout)
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
@safe_tool
async def report(domain: str) -> dict:
    """Run a full safe recon sweep of an in-scope target and return both a
    structured report and a rendered **Markdown** document, with findings
    severity-ranked. Chains: subdomains, DNS, HTTP + fingerprint, security
    headers, TLS, email posture, CORS, WAF, exposed-.git and subdomain-takeover
    checks. No intrusive scanning. In scope only.
    """

    from datetime import datetime, timezone

    host = _require_scope(domain)
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

    cors = await corsmod.audit_cors(ctx.http, apex_url)
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
# external CLI integration
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
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


@mcp.resource("findings://current")
def findings_resource() -> str:
    """The session's recorded findings (severity-ranked) with a summary."""

    import json

    return json.dumps(get_context().findings.as_dict(), indent=2)


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


def run() -> None:
    """Entry point: serve over stdio.

    The application context (and its asyncio primitives) is built lazily on the
    first tool call, i.e. inside the running event loop.
    """

    mcp.run()


if __name__ == "__main__":
    run()
