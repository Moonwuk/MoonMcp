"""DNS resolution helpers.

Pure-stdlib by default (``socket.getaddrinfo`` for A/AAAA and reverse lookups).
When ``dnspython`` is installed we additionally answer arbitrary record types
(MX, NS, TXT, CNAME, SOA, CAA) — but the server never *requires* it.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

try:  # optional dependency
    import dns.resolver  # type: ignore
    import dns.reversename  # type: ignore

    _HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover - import guard
    _HAVE_DNSPYTHON = False


@dataclass
class DnsResult:
    host: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    records: dict[str, list[str]] = field(default_factory=dict)
    canonical_name: str | None = None
    error: str | None = None
    resolver: str = "stdlib"


def _blocking_getaddrinfo(host: str) -> DnsResult:
    res = DnsResult(host=host)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        res.error = str(exc)
        return res
    a, aaaa = [], []
    for family, _type, _proto, canon, sockaddr in infos:
        if canon and res.canonical_name is None:
            res.canonical_name = canon.rstrip(".")
        ip = sockaddr[0]
        if family == socket.AF_INET and ip not in a:
            a.append(ip)
        elif family == socket.AF_INET6 and ip not in aaaa:
            aaaa.append(ip)
    res.a, res.aaaa = a, aaaa
    return res


_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def _blocking_dnspython(host: str, rdtypes: tuple[str, ...]) -> DnsResult:
    res = DnsResult(host=host, resolver="dnspython")
    resolver = dns.resolver.Resolver()
    for rdtype in rdtypes:
        try:
            answers = resolver.resolve(host, rdtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            res.error = "NXDOMAIN"
            return res
        except Exception:
            continue
        values = [r.to_text().rstrip(".") if rdtype in {"CNAME", "NS"} else r.to_text() for r in answers]
        if not values:
            continue
        res.records[rdtype] = values
        if rdtype == "A":
            res.a = values
        elif rdtype == "AAAA":
            res.aaaa = values
        elif rdtype == "CNAME" and res.canonical_name is None:
            res.canonical_name = values[0]
    return res


_DOH_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


async def resolve_doh(client, host: str, rdtypes: tuple[str, ...]) -> DnsResult:
    """Resolve full record types over DNS-over-HTTPS (dns.google JSON API).

    Gives MX/NS/TXT/CNAME/CAA/SOA support with no dnspython and no system
    resolver config — only outbound HTTPS. *client* is any object with an async
    ``fetch(url, ...)`` returning an object exposing ``.status``/``.text()``.
    """

    import json

    res = DnsResult(host=host, resolver="doh")
    for rdtype in rdtypes:
        tnum = _DOH_TYPES.get(rdtype)
        if tnum is None:
            continue
        url = f"https://dns.google/resolve?name={host}&type={rdtype}"
        r = await client.fetch(url, timeout=10.0, follow_redirects=True)
        if getattr(r, "status", None) != 200:
            continue
        try:
            data = json.loads(r.text())
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("Status") == 3:  # NXDOMAIN
            res.error = "NXDOMAIN"
            return res
        answers = [
            a.get("data", "").strip('"')
            for a in (data.get("Answer") or [])
            if isinstance(a, dict) and a.get("type") == tnum
        ]
        answers = [a.rstrip(".") if rdtype in {"CNAME", "NS"} else a for a in answers if a]
        if not answers:
            continue
        res.records[rdtype] = answers
        if rdtype == "A":
            res.a = answers
        elif rdtype == "AAAA":
            res.aaaa = answers
        elif rdtype == "CNAME" and res.canonical_name is None:
            res.canonical_name = answers[0]
    return res


async def resolve(
    host: str, rdtypes: tuple[str, ...] | None = None, http_client=None
) -> DnsResult:
    """Resolve *host*.

    Order of preference: dnspython (if installed) → DNS-over-HTTPS (if an HTTP
    client is supplied) → stdlib ``getaddrinfo`` (A/AAAA only).
    """

    types = rdtypes or _RECORD_TYPES
    if _HAVE_DNSPYTHON:
        return await asyncio.to_thread(_blocking_dnspython, host, types)
    if http_client is not None:
        result = await resolve_doh(http_client, host, types)
        # If DoH produced nothing useful, fall back to the stdlib resolver.
        if result.a or result.aaaa or result.records or result.error:
            return result
    return await asyncio.to_thread(_blocking_getaddrinfo, host)


async def reverse_lookup(ip: str) -> list[str]:
    """Return PTR names for *ip* (best effort)."""

    def _work() -> list[str]:
        try:
            name, aliases, _ = socket.gethostbyaddr(ip)
        except (socket.herror, socket.gaierror, OSError):
            return []
        names = [name] + list(aliases)
        return [n.rstrip(".") for n in names if n]

    return await asyncio.to_thread(_work)


def dnspython_available() -> bool:
    return _HAVE_DNSPYTHON
