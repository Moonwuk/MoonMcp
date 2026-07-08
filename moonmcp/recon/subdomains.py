"""Passive subdomain enumeration via free, key-less OSINT sources.

We query several public datasets in parallel and merge the results.  Everything
here is *passive* — we never send a packet to the target itself, only to the
third-party data providers — so it is safe to run before establishing scope on
the target's own infrastructure.  (The apex domain is still scope-checked by the
caller so MoonMCP only enumerates assets you are authorised to research.)

Sources (all free, no API key required):
* crt.sh              — certificate-transparency logs.
* HackerTarget        — hostsearch API.
* AnubisDB (jldc.me)  — aggregated subdomain dataset.
* AlienVault OTX      — passive DNS.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field

from ..net.http import HttpClient

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?"
_HOST_RE = re.compile(rf"(?:{_LABEL}\.)+[a-z]{{2,63}}", re.IGNORECASE)


@dataclass
class SubdomainResult:
    domain: str
    subdomains: list[str] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.subdomains)


def _clean(host: str, apex: str) -> str | None:
    host = host.strip().lower().lstrip("*.").rstrip(".")
    host = host.replace("\\n", "").strip()
    if not host or " " in host:
        return None
    if not (host == apex or host.endswith("." + apex)):
        return None
    if not _HOST_RE.fullmatch(host):
        return None
    return host


async def _crtsh(client: HttpClient, domain: str) -> tuple[str, set[str], str | None]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = await client.fetch(url, timeout=25.0, follow_redirects=True)
    if r.error or r.status != 200:
        return "crtsh", set(), r.error or f"HTTP {r.status}"
    found: set[str] = set()
    try:
        data = json.loads(r.text())
    except json.JSONDecodeError:
        # crt.sh occasionally returns concatenated JSON objects.
        try:
            data = json.loads("[" + r.text().replace("}\n{", "},{") + "]")
        except json.JSONDecodeError:
            return "crtsh", set(), "unparseable response"
    for entry in data:
        for field_name in ("name_value", "common_name"):
            val = entry.get(field_name, "")
            for line in str(val).splitlines():
                c = _clean(line, domain)
                if c:
                    found.add(c)
    return "crtsh", found, None


async def _hackertarget(client: HttpClient, domain: str) -> tuple[str, set[str], str | None]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    r = await client.fetch(url, timeout=20.0, follow_redirects=True)
    if r.error or r.status != 200:
        return "hackertarget", set(), r.error or f"HTTP {r.status}"
    text = r.text()
    if "API count exceeded" in text or "error" in text.lower()[:40]:
        return "hackertarget", set(), text.strip()[:120]
    found: set[str] = set()
    for line in text.splitlines():
        host = line.split(",")[0]
        c = _clean(host, domain)
        if c:
            found.add(c)
    return "hackertarget", found, None


async def _anubis(client: HttpClient, domain: str) -> tuple[str, set[str], str | None]:
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    r = await client.fetch(url, timeout=20.0, follow_redirects=True)
    if r.error or r.status != 200:
        return "anubis", set(), r.error or f"HTTP {r.status}"
    found: set[str] = set()
    try:
        for host in json.loads(r.text()):
            c = _clean(str(host), domain)
            if c:
                found.add(c)
    except json.JSONDecodeError:
        return "anubis", set(), "unparseable response"
    return "anubis", found, None


async def _otx(client: HttpClient, domain: str) -> tuple[str, set[str], str | None]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = await client.fetch(url, timeout=20.0, follow_redirects=True)
    if r.error or r.status != 200:
        return "otx", set(), r.error or f"HTTP {r.status}"
    found: set[str] = set()
    try:
        data = json.loads(r.text())
    except json.JSONDecodeError:
        return "otx", set(), "unparseable response"
    for rec in data.get("passive_dns", []):
        c = _clean(str(rec.get("hostname", "")), domain)
        if c:
            found.add(c)
    return "otx", found, None


_SOURCES = {
    "crtsh": _crtsh,
    "hackertarget": _hackertarget,
    "anubis": _anubis,
    "otx": _otx,
}


async def enumerate_subdomains(
    client: HttpClient,
    domain: str,
    *,
    sources: list[str] | None = None,
) -> SubdomainResult:
    domain = domain.strip().lower().lstrip("*.").rstrip(".")
    chosen = sources or list(_SOURCES)
    tasks = [_SOURCES[s](client, domain) for s in chosen if s in _SOURCES]
    result = SubdomainResult(domain=domain)
    merged: set[str] = set()
    for coro in asyncio.as_completed(tasks):
        name, found, err = await coro
        if err:
            result.errors[name] = err
        result.sources[name] = len(found)
        merged |= found
    result.subdomains = sorted(merged)
    return result


def available_sources() -> list[str]:
    return list(_SOURCES)
