"""Origin-IP discovery — finding the real server hiding behind a CDN/WAF.

A staple of authorised bug-bounty testing: a target fronted by Cloudflare/Akamai
often leaks its true origin through certificate SANs, non-proxied subdomains
(``direct``, ``origin``, ``mail``, ``cpanel``, ...), or mail infrastructure.  If
you can reach the origin directly you can test the real application without the
WAF in the way.  This tool collects candidate origin IPs and flags the ones that
sit on *different* infrastructure than the CDN front.

Passive+light: DNS + TLS + a bounded set of ip-intel lookups; it does not attack
the origin, only identifies it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..intel.asn import ip_intel
from ..net.dns import resolve
from ..net.http import HttpClient
from ..net.tls import inspect_certificate

_CDN_CLOUDS = {"Cloudflare", "Akamai", "Fastly", "AWS CloudFront", "Gcore"}
_ORIGIN_SUBS = [
    "origin", "direct", "direct-connect", "origin-www", "www2", "web",
    "cpanel", "whm", "webmail", "mail", "smtp", "ftp", "dev", "staging",
    "test", "portal", "vpn", "remote", "backend", "api", "admin", "server",
]


@dataclass
class OriginCandidate:
    ip: str
    source: str            # e.g. "SAN:foo.example", "subdomain:origin", "MX"
    cloud: str | None = None
    asn: str | None = None
    is_cdn: bool = False


@dataclass
class OriginResult:
    host: str
    front_ips: list[str] = field(default_factory=list)
    front_cloud: str | None = None
    behind_cdn: bool = False
    candidates: list[OriginCandidate] = field(default_factory=list)
    likely_origins: list[str] = field(default_factory=list)
    error: str | None = None


async def discover_origin(
    client: HttpClient, host: str, *, scope_check=None, max_lookups: int = 12
) -> OriginResult:
    result = OriginResult(host=host)
    apex = host

    front = await resolve(host, rdtypes=("A", "CNAME"), http_client=client)
    result.front_ips = front.a
    if not front.a:
        result.error = "host does not resolve to an A record"
        return result

    front_intel = await ip_intel(client, front.a[0])
    result.front_cloud = front_intel.cloud
    result.behind_cdn = front_intel.cloud in _CDN_CLOUDS

    # Collect candidate hostnames: cert SANs + common origin subdomains + MX.
    candidate_hosts: dict[str, str] = {}
    tls = await inspect_certificate(host, 443)
    for san in tls.subject_alt_names:
        san = san.lstrip("*.").lower()
        if san and san != host:
            candidate_hosts[san] = f"SAN:{san}"
    if "." in apex:
        base = apex.split(".", 1)[1] if apex.count(".") >= 2 else apex
        for sub in _ORIGIN_SUBS:
            candidate_hosts.setdefault(f"{sub}.{base}", f"subdomain:{sub}")
    mx = await resolve(apex, rdtypes=("MX",), http_client=client)
    for rec in mx.records.get("MX", []):
        mxhost = rec.split()[-1].rstrip(".").lower() if rec.split() else ""
        if mxhost:
            candidate_hosts.setdefault(mxhost, "MX")

    front_set = set(front.a)
    seen_ips: dict[str, OriginCandidate] = {}
    lookups = 0
    for chost, source in candidate_hosts.items():
        r = await resolve(chost, rdtypes=("A",), http_client=client)
        for ip in r.a:
            if ip in front_set or ip in seen_ips:
                continue
            cand = OriginCandidate(ip=ip, source=source)
            if lookups < max_lookups:
                intel = await ip_intel(client, ip)
                cand.cloud = intel.cloud
                cand.asn = intel.asn
                cand.is_cdn = intel.cloud in _CDN_CLOUDS
                lookups += 1
            seen_ips[ip] = cand

    result.candidates = list(seen_ips.values())
    # Likely origins: IPs that are NOT on the same CDN as the front.
    result.likely_origins = sorted({
        c.ip for c in result.candidates
        if not c.is_cdn and (c.cloud != result.front_cloud or result.front_cloud is None)
    })
    return result
