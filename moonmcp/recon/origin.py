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

# Common multi-label public suffixes. When a host's last two labels form one of
# these, the registrable domain keeps THREE labels (example.co.uk), not two —
# otherwise the base derivation strips a real label and yields candidate hosts
# under the public suffix (mail.co.uk), directing testing at unrelated domains.
_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "govt.nz",
    "co.jp", "or.jp", "ne.jp", "go.jp", "co.kr", "or.kr", "co.za", "org.za",
    "com.br", "net.br", "gov.br", "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.in", "net.in", "org.in", "gov.in", "com.mx", "com.tr", "com.sg",
    "com.hk", "com.tw", "co.il", "com.ar", "com.ua", "com.ru", "com.pl",
})


def _registrable_base(apex: str) -> str:
    """The registrable domain of *apex* — the label below its public suffix —
    handling multi-label suffixes (example.co.uk stays example.co.uk, not co.uk)."""

    labels = apex.split(".")
    n = 3 if ".".join(labels[-2:]) in _MULTI_SUFFIXES else 2
    return ".".join(labels[-n:]) if len(labels) >= n else apex


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
    client: HttpClient, host: str, *, max_lookups: int = 12
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
        base = _registrable_base(apex)
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
            if c.enriched and not c.is_cdn and c.cloud != result.front_cloud
        })
    return result
