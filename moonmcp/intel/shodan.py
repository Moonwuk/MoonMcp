"""Host intelligence via Shodan.

Two tiers, both handled here:
* **InternetDB** (``https://internetdb.shodan.io/<ip>``) — free, no API key,
  returns open ports, hostnames, CPEs, tags and known CVEs for an IP.
* **Full Shodan API** — used automatically when an API key is configured, for
  richer host detail.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field

from ..net.http import HttpClient


@dataclass
class ShodanHost:
    ip: str
    source: str = "internetdb"
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    org: str | None = None
    os: str | None = None
    error: str | None = None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def internetdb_lookup(client: HttpClient, ip: str) -> ShodanHost:
    host = ShodanHost(ip=ip)
    if not _is_ip(ip):
        host.error = "InternetDB requires an IP address, not a hostname"
        return host
    r = await client.fetch(f"https://internetdb.shodan.io/{ip}", timeout=15.0, follow_redirects=True)
    if r.status == 404:
        host.error = "no InternetDB record for this IP"
        return host
    if r.error or r.status != 200:
        host.error = r.error or f"HTTP {r.status}"
        return host
    try:
        data = json.loads(r.text())
    except json.JSONDecodeError:
        host.error = "unparseable response"
        return host
    host.ports = data.get("ports", [])
    host.hostnames = data.get("hostnames", [])
    host.cpes = data.get("cpes", [])
    host.vulns = data.get("vulns", [])
    host.tags = data.get("tags", [])
    return host


async def shodan_host_lookup(client: HttpClient, ip: str, api_key: str) -> ShodanHost:
    host = ShodanHost(ip=ip, source="shodan-api")
    if not _is_ip(ip):
        host.error = "Shodan host lookup requires an IP address"
        return host
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    r = await client.fetch(url, timeout=20.0, follow_redirects=True)
    if r.error or r.status != 200:
        # Gracefully fall back to the free dataset.
        fallback = await internetdb_lookup(client, ip)
        fallback.error = (fallback.error or "") + f" (shodan API HTTP {r.status})"
        return fallback
    try:
        data = json.loads(r.text())
    except json.JSONDecodeError:
        host.error = "unparseable response"
        return host
    host.ports = sorted(set(data.get("ports", [])))
    host.hostnames = data.get("hostnames", [])
    host.vulns = list(data.get("vulns", []) or [])
    host.tags = data.get("tags", []) or []
    host.org = data.get("org")
    host.os = data.get("os")
    host.cpes = sorted({cpe for item in data.get("data", []) for cpe in item.get("cpe", []) or []})
    return host


async def host_intel(client: HttpClient, ip: str, api_key: str | None = None) -> ShodanHost:
    if api_key:
        return await shodan_host_lookup(client, ip, api_key)
    return await internetdb_lookup(client, ip)
