"""IP infrastructure intelligence: ASN / org / cloud / geo, and reverse-IP.

Passive: talks to free third-party datasets (ip-api.com, HackerTarget), not the
target.  ``ip_intel`` maps an IP to its ASN, organisation, hosting/cloud provider
and geo; ``reverse_ip`` lists other domains co-hosted on the same address (great
for widening scope and for spotting shared infrastructure).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field

from ..net.http import HttpClient

# substring -> cloud/CDN provider name
_CLOUD_MARKERS = {
    "amazon": "AWS", "aws": "AWS", "ec2": "AWS", "cloudfront": "AWS CloudFront",
    "google": "Google Cloud", "goog": "Google Cloud",
    "microsoft": "Azure", "azure": "Azure",
    "cloudflare": "Cloudflare", "fastly": "Fastly", "akamai": "Akamai",
    "digitalocean": "DigitalOcean", "linode": "Linode", "ovh": "OVH",
    "hetzner": "Hetzner", "oracle": "Oracle Cloud", "vultr": "Vultr",
    "alibaba": "Alibaba Cloud", "leaseweb": "LeaseWeb", "gcore": "Gcore",
}


@dataclass
class IpIntel:
    ip: str
    asn: str | None = None
    as_name: str | None = None
    org: str | None = None
    isp: str | None = None
    cloud: str | None = None
    is_hosting: bool | None = None
    country: str | None = None
    city: str | None = None
    reverse_dns: str | None = None
    error: str | None = None


def _detect_cloud(*fields: str | None) -> str | None:
    blob = " ".join(f for f in fields if f).lower()
    for marker, name in _CLOUD_MARKERS.items():
        if marker in blob:
            return name
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def ip_intel(client: HttpClient, ip: str) -> IpIntel:
    ip = ip.strip()
    result = IpIntel(ip=ip)
    if not _is_ip(ip):
        result.error = "ip_intel requires an IP address"
        return result
    url = (f"http://ip-api.com/json/{ip}"
           "?fields=status,message,country,city,isp,org,as,asname,reverse,hosting,query")
    r = await client.fetch(url, timeout=15.0, follow_redirects=True)
    if r.status != 200 or not r.body:
        result.error = r.error or f"HTTP {r.status}"
        return result
    try:
        data = json.loads(r.text())
    except (json.JSONDecodeError, ValueError):
        result.error = "unparseable response"
        return result
    if not isinstance(data, dict) or data.get("status") != "success":
        result.error = data.get("message", "lookup failed") if isinstance(data, dict) else "bad response"
        return result
    as_field = data.get("as") or ""
    result.asn = as_field.split()[0] if as_field.startswith("AS") else None
    result.as_name = data.get("asname") or (" ".join(as_field.split()[1:]) or None)
    result.org = data.get("org") or None
    result.isp = data.get("isp") or None
    result.country = data.get("country") or None
    result.city = data.get("city") or None
    result.reverse_dns = data.get("reverse") or None
    result.is_hosting = bool(data.get("hosting"))
    result.cloud = _detect_cloud(result.org, result.isp, result.as_name)
    return result


@dataclass
class ReverseIp:
    ip: str
    domains: list[str] = field(default_factory=list)
    count: int = 0
    error: str | None = None


async def reverse_ip(client: HttpClient, ip: str) -> ReverseIp:
    ip = ip.strip()
    result = ReverseIp(ip=ip)
    if not _is_ip(ip):
        result.error = "reverse_ip requires an IP address"
        return result
    r = await client.fetch(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                           timeout=20.0, follow_redirects=True)
    if r.status != 200 or not r.body:
        result.error = r.error or f"HTTP {r.status}"
        return result
    text = r.text()
    if "error" in text.lower()[:40] or "API count exceeded" in text:
        result.error = text.strip()[:120]
        return result
    domains = sorted({line.strip().lower() for line in text.splitlines()
                      if line.strip() and "." in line and " " not in line.strip()})
    result.domains = domains
    result.count = len(domains)
    return result
