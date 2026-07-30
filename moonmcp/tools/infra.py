"""Behavioural-infrastructure detectors — infer the infra from response *variance*.

Extracted from server.py. Active (scope-gated) tools that cluster/measure response
behaviour: backend fleet, DNS/zone, vhost routing, rate-limit, TLS routing, edge
topology and raw HTTP fingerprint. Importing this module registers them on the
shared `mcp` instance.
"""

from __future__ import annotations

from ..mcp_core import (
    _connect_pin,
    _scope_check,
    _split_host_port,
    active_tool,
    get_context,
    mcp,
)
from ..net import dns as dnsmod
from ..net import tls as tlsmod
from ..recon import infra as inframod
from ..scope import canonical_ip, normalize_target
from ..web import desync as desyncmod


@mcp.tool()
@active_tool()
async def backend_probe(target: str, samples: int = 12) -> dict:
    """**Infer the backend fleet behind a load balancer** from response variance.
    Sends N benign requests and clusters them by their discriminators (Server,
    X-Powered-By, Via, backend-id headers, Set-Cookie names, **response
    header-name ordering**) to count distinct backends, and flags **patch drift**
    (nodes reporting different Server versions — a lagging node may be individually
    vulnerable), **content drift** (nodes serving different ETag/Last-Modified for the
    same URL — build/deploy inconsistency), and **clock skew** between nodes. The
    load-balancing/consistency picture a single request can't show. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    n = max(3, min(samples, 30))
    out: list[dict] = []
    for _ in range(n):
        r = await ctx.http.fetch(url, method="GET", follow_redirects=False, scope_check=_scope_check())
        out.append({
            "server": r.header("Server"),
            "powered_by": r.header("X-Powered-By"),
            "via": r.header("Via"),
            # X-Served-By is a CDN cache-node id (unique per edge PoP) → excluded so
            # it doesn't inflate the backend count; prefer origin-identifying headers.
            "backend": r.header("X-Backend-Server") or r.header("X-Server"),
            "cookies": [c.split("=", 1)[0].strip() for c in r.get_all("set-cookie")],
            "etag": r.header("ETag"),
            "last_modified": r.header("Last-Modified"),
            # header-name order (lowercased) — a covert per-backend fingerprint.
            "header_order": tuple(k.lower() for k, _ in r.headers),
            "date_epoch": inframod.parse_http_date(r.header("Date")),
            "elapsed_ms": r.elapsed_ms,
        })
    return {"target": url, "samples": n, **inframod.cluster_backends(out)}


@mcp.tool()
@active_tool()
async def dns_behavior(domain: str) -> dict:
    """**Behavioural DNS / zone profiling.** Detects **wildcard DNS** (so subdomain
    enumeration isn't fooled by catch-all resolution), whether the zone is
    **DNS-load-balanced** (multiple/rotating A records), IPv6 presence, and the
    CNAME target (dangling-CNAME → takeover surface). Passive DNS; in scope only.
    """

    host = normalize_target(domain)
    ctx = get_context()
    # An IP literal resolves to itself — no DNS/DoH round-trip, no wildcard/CNAME.
    ip = canonical_ip(host)
    if ip is not None:
        is6 = ip.version == 6
        return {"host": host, "wildcard_dns": False,
                "a_records": [] if is6 else [host], "aaaa_records": [host] if is6 else [],
                "ipv6": is6, "dns_load_balanced": False, "cname": None,
                "nameservers": [], "mx": [], "concerns": []}
    import secrets
    rand = f"moonwild{secrets.token_hex(6)}.{host}"
    wild = await dnsmod.resolve(rand, http_client=ctx.http)
    wildcard = bool(wild.a or wild.aaaa)

    a_sets: list[tuple[str, ...]] = []
    base = None
    for _ in range(3):
        rr = await dnsmod.resolve(host, http_client=ctx.http)
        base = base or rr
        a_sets.append(tuple(sorted(rr.a)))
    assert base is not None
    dns_lb = len({s for s in a_sets if s}) > 1 or len(base.a) > 1
    records = base.records or {}
    concerns: list[str] = []
    if wildcard:
        concerns.append("wildcard DNS is enabled — verify enumerated subdomains actually resolve "
                        "distinctly (catch-all inflates false positives)")
    if base.canonical_name:
        concerns.append(f"apex/host is a CNAME to {base.canonical_name} — check it is not a "
                        "dangling pointer to an unclaimed service (takeover)")
    return {
        "host": host,
        "wildcard_dns": wildcard,
        "a_records": base.a,
        "aaaa_records": base.aaaa,
        "ipv6": bool(base.aaaa),
        "dns_load_balanced": dns_lb,
        "cname": base.canonical_name,
        "nameservers": records.get("NS", []),
        "mx": records.get("MX", []),
        "concerns": concerns,
    }


@mcp.tool()
@active_tool()
async def vhost_probe(target: str) -> dict:
    """**Host-header routing behaviour.** Compares the normal response with one sent
    under a **bogus Host** header to reveal how the edge routes: does it **validate
    the Host** (routes/errors) or serve the same app regardless (host-header
    attacks — cache poisoning, password-reset poisoning, routing to internal
    vhosts)? Also checks whether the bogus host is **reflected** (host-header
    injection) directly or via `X-Forwarded-Host`. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    bogus = "moonvhost-notreal.example"
    # Two identical baseline requests first → measure the page's natural jitter so
    # a dynamic page (timestamps, CSRF tokens) isn't mistaken for host validation.
    base = await ctx.http.fetch(url, follow_redirects=False, scope_check=_scope_check())
    base2 = await ctx.http.fetch(url, follow_redirects=False, scope_check=_scope_check())
    bh = await ctx.http.fetch(url, headers={"Host": bogus}, follow_redirects=False, scope_check=_scope_check())
    xfh = await ctx.http.fetch(url, headers={"X-Forwarded-Host": bogus}, follow_redirects=False,
                               scope_check=_scope_check())

    base_body = base.text(200_000)
    jitter = abs(len(base.body) - len(base2.body))
    host_validated = (bh.status != base.status) or (abs(len(bh.body) - len(base.body)) > jitter + 256)

    def _reflects(r) -> bool:
        # Reflected in the body OR echoed into a routing/redirect header.
        if bogus in r.text(200_000) and bogus not in base_body:
            return True
        for h in ("Location", "Refresh", "Content-Location", "Link"):
            if bogus in (r.header(h) or ""):
                return True
        return False

    reflected_host = _reflects(bh)
    reflected_xfh = _reflects(xfh)
    concerns: list[str] = []
    if not host_validated:
        concerns.append("the edge serves the same app for an arbitrary Host — host-header not "
                        "validated (routing / cache-poisoning / reset-poisoning surface)")
    if reflected_host or reflected_xfh:
        via = "Host" if reflected_host else "X-Forwarded-Host"
        concerns.append(f"bogus host reflected via {via} — host-header injection "
                        "(open-redirect / cache-poisoning / password-reset poisoning)")
    return {
        "target": url,
        "host_validated": host_validated,
        "host_header_reflected": reflected_host,
        "x_forwarded_host_reflected": reflected_xfh,
        "baseline": {"status": base.status, "length": len(base.body)},
        "bogus_host": {"status": bh.status, "length": len(bh.body)},
        "concerns": concerns,
    }


@mcp.tool()
@active_tool(intrusive=True)
async def ratelimit_probe(target: str, burst: int = 20) -> dict:
    """**Rate-limit / throttling behaviour profile.** Sends a bounded burst
    (rate-limiter-respecting) and reports whether the endpoint throttles, at which
    request it first blocks (429/403/503), any `Retry-After`, and — crucially —
    whether spoofing `X-Forwarded-For` **resets** the counter (the limiter keys on
    a client-controlled IP header → per-IP bypass). A missing limit on a sensitive
    endpoint is a brute-force / enumeration / resource-exhaustion finding.
    Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    n = max(5, min(burst, 40))
    statuses: list[int | None] = []
    first_block: int | None = None
    retry_after: str | None = None
    for i in range(n):
        r = await ctx.http.fetch(url, follow_redirects=False, scope_check=_scope_check())
        statuses.append(r.status)
        if r.status in (429, 403, 503):
            if first_block is None:
                first_block = i + 1
                retry_after = r.header("Retry-After")
    bypass_reset: bool | None = None
    if first_block is not None:
        import secrets
        spoof = f"10.{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}"
        r = await ctx.http.fetch(url, headers={"X-Forwarded-For": spoof}, follow_redirects=False,
                                 scope_check=_scope_check())
        bypass_reset = r.status not in (429, 403, 503)
    return {"target": url,
            **inframod.ratelimit_summary(statuses, first_block=first_block,
                                         retry_after=retry_after, bypass_reset=bypass_reset)}


@mcp.tool()
@active_tool()
async def tls_behavior(target: str, port: int = 443) -> dict:
    """**Behavioural TLS profiling.** Compares the certificate served for the real
    host vs a **bogus SNI** — if a valid cert for another domain comes back, the
    edge is SNI-routing/shared-hosting (a default-backend / origin-exposure hint);
    if identical, the host doesn't route on SNI. **Mines the default (bogus-SNI)
    cert's SANs** for `origin_hostname_hints` — sibling tenants or the origin's own
    hostname to pivot on. Also reports supported TLS versions (flagging weak TLS
    1.0/1.1), the negotiated cipher, and HTTP/2 (ALPN). In scope only.
    """

    host, tls_port = _split_host_port(target, port)
    ctx = get_context()
    real = await tlsmod.inspect_certificate(host, tls_port, timeout=ctx.settings.timeout,
                                            server_name=host, connect_pin=_connect_pin())
    bogus = await tlsmod.inspect_certificate(host, tls_port, timeout=ctx.settings.timeout,
                                             server_name="moontls-notreal.example", connect_pin=_connect_pin())
    profile = await tlsmod.probe_tls_profile(host, tls_port, timeout=ctx.settings.timeout, connect_pin=_connect_pin())
    if not real.connected:
        return {"target": host, "port": tls_port, "error": "tls_handshake_failed",
                "detail": real.error}
    real_serial = real.serial_number
    bogus_serial = bogus.serial_number if bogus.connected else None
    sni_routing = bool(bogus_serial) and bogus_serial != real_serial
    # Mine the DEFAULT (bogus-SNI) cert's SANs for origin/tenant hostnames — the cert an
    # edge serves when it doesn't recognise the SNI often names the origin or a sibling.
    default_sans = bogus.subject_alt_names if (bogus.connected and sni_routing) else []
    origin_hints = tlsmod.origin_hostname_hints(host, default_sans)
    concerns: list[str] = []
    if profile.weak_versions:
        concerns.append(f"weak TLS versions accepted: {', '.join(profile.weak_versions)}")
    if sni_routing:
        concerns.append("a different certificate is served for an unknown SNI — SNI-based routing "
                        "/ shared hosting; the default cert may expose another tenant or the origin")
    if origin_hints:
        concerns.append(f"the default certificate names other hosts {origin_hints[:8]} — sibling "
                        "tenants or the origin hostname; pivot on these for origin/lateral surface")
    if real.expired:
        concerns.append("the certificate is expired")
    return {
        "target": host, "port": tls_port,
        "certificate": {"subject": real.subject.get("commonName"), "issuer": real.issuer.get("organizationName"),
                        "san": real.subject_alt_names[:20], "serial": real_serial,
                        "not_after": real.not_after, "days_until_expiry": real.days_until_expiry},
        "sni_routing": sni_routing,
        "default_cert": {
            "subject": bogus.subject.get("commonName") if bogus.connected else None,
            "issuer": bogus.issuer.get("organizationName") if bogus.connected else None,
            "san": default_sans[:20],
        },
        "default_cert_subject": bogus.subject.get("commonName") if bogus.connected else None,
        "origin_hostname_hints": origin_hints[:20],
        "supported_versions": profile.supported_versions,
        "weak_versions": profile.weak_versions,
        "http2": profile.http2,
        "negotiated_cipher": real.cipher,
        "concerns": concerns,
    }


@mcp.tool()
@active_tool()
async def edge_map(target: str) -> dict:
    """**Map the edge topology** in front of the origin: which CDN/WAF/cache
    vendors (Cloudflare, CloudFront, Fastly, Akamai, Sucuri, Imperva, …), the proxy
    chain (`Via`), and whether a cache layer is present — from the response
    headers. Tells you whether you're hitting an edge (and should hunt the origin)
    or the origin directly. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    r = await ctx.http.fetch(url, follow_redirects=True, max_redirects=ctx.settings.max_redirects,
                             scope_check=_scope_check())
    if r.status is None:
        return {"error": "unreachable", "detail": r.error, "url": url}
    layers = inframod.edge_layers(r.headers_map())
    return {"target": url, "status": r.status, "server": r.header("Server"), **layers}


@mcp.tool()
@active_tool(intrusive=True)
async def http_behavior(target: str) -> dict:
    """**Raw HTTP/1.x behaviour fingerprint.** Sends a handful of complete
    edge-case requests on fresh connections — HTTP/1.0, an unknown method, an
    oversized header, **bare-LF** and **bare-CR** line endings, **obsolete line
    folding** (obs-fold), and **duplicate Content-Length** — and reports how the
    stack reacts. Accepting any of these points at **lenient parsing / a proxy-origin
    mismatch** (request-smuggling surface); confirm with desync_modern_probe.
    Detection-only (complete requests, nothing left to poison a connection).
    Intrusive; in scope only.
    """

    from urllib.parse import urlsplit

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    sp = urlsplit(url)
    host = sp.hostname or ""
    tls = sp.scheme == "https"
    hport = sp.port or (443 if tls else 80)
    path = sp.path or "/"
    ctx = get_context()
    t = ctx.settings.timeout

    async def _raw(data: bytes) -> bytes | None:
        return await desyncmod._raw_request(host, hport, tls, data, t, connect_pin=_connect_pin())

    ua = f"User-Agent: {ctx.settings.user_agent}\r\n"
    base = await _raw(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{ua}Connection: close\r\n\r\n".encode("latin-1"))
    http10 = await _raw(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n{ua}\r\n".encode("latin-1"))
    badm = await _raw(f"MOONX {path} HTTP/1.1\r\nHost: {host}\r\n{ua}Connection: close\r\n\r\n".encode("latin-1"))
    big = await _raw((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{ua}X-Big: "
                      + "A" * 16384 + "\r\nConnection: close\r\n\r\n").encode("latin-1"))
    # Bare-LF (no CR) line endings — lenient parsers accept this.
    lf = await _raw(f"GET {path} HTTP/1.1\nHost: {host}\n{ua.replace(chr(13), '')}Connection: close\n\n".encode("latin-1"))
    # Bare-CR (no LF) line endings.
    cr = await _raw(f"GET {path} HTTP/1.1\rHost: {host}\r{ua.replace(chr(13), chr(13))}Connection: close\r\r".encode("latin-1"))
    # Obsolete line folding (obs-fold): a header value continued on the next line.
    fold = await _raw((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{ua}X-Fold: a\r\n b\r\n"
                       "Connection: close\r\n\r\n").encode("latin-1"))
    # Duplicate Content-Length (RFC 7230 says reject) — CL.CL framing ambiguity.
    dupcl = await _raw((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{ua}Content-Length: 0\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n").encode("latin-1"))

    base_status, base_server = desyncmod._status_of(base) if base else (None, None)
    conn = None
    if base:
        for hl in base.split(b"\r\n"):
            if hl.lower().startswith(b"connection:"):
                conn = hl.split(b":", 1)[1].strip().decode("latin-1", "replace")
                break
    summary = inframod.summarize_http_behavior(
        baseline_status=base_status, connection=conn,
        http10_status=desyncmod._status_of(http10)[0] if http10 else None,
        invalid_method_status=desyncmod._status_of(badm)[0] if badm else None,
        oversized_status=desyncmod._status_of(big)[0] if big else None,
        bare_lf_status=desyncmod._status_of(lf)[0] if lf else None,
        bare_cr_status=desyncmod._status_of(cr)[0] if cr else None,
        obs_fold_status=desyncmod._status_of(fold)[0] if fold else None,
        dup_cl_status=desyncmod._status_of(dupcl)[0] if dupcl else None,
    )
    return {"target": url, "server": base_server, **summary}
