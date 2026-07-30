"""Network / infra fingerprinting — favicon hash, TLS version+cipher, JARM, origin
discovery behind a CDN, and behavioural response profiling.

Extracted from server.py. Scope-gated; importing registers them on `mcp`.
"""

from __future__ import annotations

from ..context import to_dict
from ..mcp_core import (
    _connect_pin,
    _scope_check,
    _split_host_port,
    active_tool,
    get_context,
    mcp,
)
from ..net import jarm as jarmmod
from ..net import tls as tlsmod
from ..recon import favicon as faviconmod
from ..recon import origin as originmod
from ..scope import normalize_target
from ..web import behavior as behaviormod


@mcp.tool()
@active_tool()
async def favicon_hash(target: str) -> dict:
    """Compute an in-scope site's favicon hash (Shodan-style mmh3). Two hosts
    sharing a favicon hash are usually the same product/instance, so the returned
    `http.favicon.hash:<hash>` query lets you pivot on Shodan/Censys/FOFA to find
    sibling assets — including origin servers hiding behind a CDN. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await faviconmod.fetch_favicon_hash(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def tls_fingerprint(target: str, port: int = 443) -> dict:
    """Profile a host's TLS configuration: which protocol versions it supports
    (flagging weak TLS 1.0/1.1), the cipher per version, and ALPN / HTTP-2
    support. A compact server-side TLS fingerprint for infra mapping and posture.
    In scope only.
    """

    host, tls_port = _split_host_port(target, port)
    result = await tlsmod.probe_tls_profile(host, tls_port, timeout=get_context().settings.timeout, connect_pin=_connect_pin())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def jarm_fingerprint(target: str, port: int = 443) -> dict:
    """Compute the **JARM** active TLS fingerprint of an in-scope host (Salesforce's
    62-char server fingerprint from 10 crafted TLS handshakes). Two servers with
    the same JARM are configured identically at the TLS layer — a strong pivot for
    finding sibling infrastructure / origin servers and for matching known stacks
    (or C2) in public JARM databases. In scope only.
    """

    host, jport = _split_host_port(target, port)
    ctx = get_context()
    result = await jarmmod.compute_jarm(host, jport, timeout=max(10.0, ctx.settings.timeout), connect_pin=_connect_pin())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def origin_discovery(domain: str) -> dict:
    """Try to find the real origin IP behind a CDN/WAF for an in-scope host.
    Resolves the front IPs and detects the CDN, then hunts candidate origins via
    certificate SANs, common non-proxied subdomains (origin/direct/mail/cpanel/…)
    and MX records, flagging IPs that sit on *different* infrastructure than the
    CDN front. Passive+light. In scope only.
    """

    host = normalize_target(domain)
    ctx = get_context()
    result = await originmod.discover_origin(ctx.http, host)
    return to_dict(result)


@mcp.tool()
@active_tool()
async def behavior_probe(target: str) -> dict:
    """Profile how an in-scope target *behaves*: 404 handling (soft-404 / custom),
    stack-trace / error disclosure, Host and X-Forwarded-Host reflection
    (cache-poisoning / host-header-injection hints), advertised methods and
    response time. Light, benign requests only. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await behaviormod.profile_behavior(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)
