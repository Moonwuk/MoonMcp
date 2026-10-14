"""Network tools with injected context and scope gates."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..context import AppContext
from ..net import dns as dnsmod
from ..net import tls as tlsmod
from ..recon import content as contentmod
from ..recon import fingerprint as fpmod
from ..recon import headers as headersmod
from ..scope import normalize_target
from . import local_registration, object_payload


def register(mcp: Any, active_tool: Callable,
             get_context: Callable[[], AppContext], _scope_check: Callable,
             _split_host_port: Callable[[str, int], tuple[str, int]]) -> dict[str, Callable]:
    """Bind tools without importing the server or creating shared state."""
    exported: dict[str, Callable] = {}
    tool = local_registration(mcp, lambda fn: fn, exported)

    @tool
    @active_tool()
    async def dns_lookup(target: str) -> dict:
        """Resolve a host's DNS records (A/AAAA, plus MX/NS/TXT/CNAME/SOA/CAA when
        dnspython is installed) and attempt a reverse PTR lookup on its A records.
        Requires the target to be in scope.
        """

        host = normalize_target(target)
        result = await dnsmod.resolve(host, http_client=get_context().http)
        data = object_payload(result)
        ptr = {}
        for ip in (result.a or [])[:3]:
            names = await dnsmod.reverse_lookup(ip)
            if names:
                ptr[ip] = names
        if ptr:
            data["ptr"] = ptr
        return data

    @tool
    @active_tool()
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
        host = normalize_target(url)
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

    @tool
    @active_tool()
    async def tls_inspect(target: str, port: int = 443) -> dict:
        """Inspect a host's TLS certificate: subject, issuer, validity window, days
        until expiry, negotiated protocol/cipher, and — most useful for recon — the
        Subject Alternative Names, which often reveal sibling hostnames. In scope only.
        """

        host, tls_port = _split_host_port(target, port)
        result = await tlsmod.inspect_certificate(host, tls_port, timeout=get_context().settings.timeout)
        return object_payload(result)

    @tool
    @active_tool()
    async def analyze_headers(target: str) -> dict:
        """Fetch a URL and audit its HTTP security headers.

        Grades (A-F) the presence of HSTS, CSP, X-Frame-Options, X-Content-Type-
        Options, Referrer-Policy and Permissions-Policy; flags information-leaking
        headers (Server, X-Powered-By, ...) and risky Set-Cookie flags. In scope only.
        """

        raw = target.strip()
        url = raw if "://" in raw else f"https://{raw}"
        ctx = get_context()
        result = await ctx.http.fetch(
            url, follow_redirects=True, max_redirects=ctx.settings.max_redirects, scope_check=_scope_check()
        )
        if result.status is None:
            return {"error": "unreachable", "detail": result.error, "url": url}
        audit = headersmod.audit_headers(result)
        return object_payload(audit)

    @tool
    @active_tool()
    async def fingerprint(target: str) -> dict:
        """Fetch a URL and fingerprint its technology stack: web server, CDN/WAF,
        language/runtime, frameworks, CMS and front-end libraries, with version hints
        and the evidence for each match. In scope only.
        """

        raw = target.strip()
        url = raw if "://" in raw else f"https://{raw}"
        host = normalize_target(url)
        ctx = get_context()
        result = await ctx.http.fetch(
            url, follow_redirects=True, max_redirects=ctx.settings.max_redirects, scope_check=_scope_check()
        )
        if result.status is None:
            return {"error": "unreachable", "detail": result.error, "url": url}
        dns_res = await dnsmod.resolve(host, http_client=ctx.http)
        ip = dns_res.a[0] if dns_res.a else None
        fp = fpmod.fingerprint(result, ip=ip)
        return object_payload(fp)

    @tool
    @active_tool()
    async def well_known(target: str) -> dict:
        """Fetch and parse a host's disclosure files: robots.txt (extracting the
        referenced paths), sitemap.xml (extracting <loc> URLs), security.txt and
        humans.txt. A quick, low-noise way to discover structure. In scope only.
        """

        host, port = _split_host_port(target, 443)
        raw = target.strip()
        scheme = "http" if raw.startswith("http://") else "https"
        ctx = get_context()
        result = await contentmod.fetch_well_known(
            ctx.http, host, scheme=scheme, port=port, scope_check=_scope_check()
        )
        return object_payload(result)

    return exported
