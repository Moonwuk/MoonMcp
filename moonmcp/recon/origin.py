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

# Common multi-label public suffixes — without a full PSL, enough to avoid grafting
# origin-subdomains onto a bare suffix (example.co.uk must not become mail.co.uk, an
# UNRELATED third-party domain).
_PUBLIC_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "net.nz", "org.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "co.za", "org.za",
    "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "com.tr", "com.sg", "com.hk", "com.tw", "co.in", "net.in", "org.in",
    "com.ar", "com.co", "co.il", "com.my", "co.id", "com.ua", "com.ph", "com.pk",
})


def _origin_base(apex: str) -> str:
    """The registrable base to graft origin-subdomains onto. Stripping the leftmost
    label of example.co.uk yields the bare suffix co.uk — grafting mail./origin. onto
    that enumerates unrelated third-party domains, so keep the apex in that case."""

    parts = apex.split(".")
    if len(parts) <= 2:
        return apex
    stripped = ".".join(parts[1:])
    return apex if stripped.lower() in _PUBLIC_SUFFIXES else stripped


@dataclass
class OriginCandidate:
    ip: str
    source: str            # e.g. "SAN:foo.example", "subdomain:origin", "MX"
    cloud: str | None = None
    asn: str | None = None
    is_cdn: bool = False
    enriched: bool = False  # True once ip_intel actually ran (cloud/asn are trustworthy)


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
    client: HttpClient, host: str, *, max_lookups: int = 12, connect_pin=None
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
    # Pin the vetted IP for the target's cert inspection — inspect_certificate otherwise
    # re-resolves `host` and connects to whatever DNS returns (DNS-rebinding TOCTOU /
    # a mixed-A-record internal IP), unlike the other raw-socket tools.
    tls = await inspect_certificate(host, 443, connect_pin=connect_pin)
    for san in tls.subject_alt_names:
        san = san.lstrip("*.").lower()
        if san and san != host:
            candidate_hosts[san] = f"SAN:{san}"
    if "." in apex:
        base = _origin_base(apex)
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
                cand.enriched = True
                lookups += 1
            seen_ips[ip] = cand

    result.candidates = list(seen_ips.values())
    # Likely origins only make sense when the front is actually CDN-fronted, and
    # only for candidates we ENRICHED and confirmed sit off that CDN. Without this
    # gate, a rate-limited front lookup (front_cloud=None) or an un-enriched
    # candidate (past max_lookups, cloud=None) would be reported as a bogus origin.
    if result.behind_cdn:
        result.likely_origins = sorted({
            c.ip for c in result.candidates
            # An MX points at mail infra (often a SHARED provider — Google/Outlook), not
            # the web origin; keep it as a candidate but never a likely web origin. The
            # self-hosted-mail case is still caught via the `subdomain:mail` candidate.
            if c.enriched and not c.is_cdn and c.cloud != result.front_cloud and c.source != "MX"
        })
    return result
