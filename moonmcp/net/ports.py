"""Async TCP connect-scan using asyncio streams (no raw sockets, no root).

A connect scan is the safest, most portable form of port scanning: it performs a
full TCP handshake, so it never sends malformed packets and works unprivileged.
Concurrency is bounded so we never open thousands of sockets at once.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

# A pragmatic default set of interesting ports for web-app recon.
TOP_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1723: "pptp",
    2082: "cpanel",
    2083: "cpanel-ssl",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    9300: "elasticsearch",
    10000: "webmin",
    11211: "memcached",
    27017: "mongodb",
}


@dataclass
class PortState:
    port: int
    open: bool
    service: str | None = None
    banner: str | None = None


@dataclass
class ScanResult:
    host: str
    open_ports: list[PortState] = field(default_factory=list)
    scanned: int = 0
    duration_ms: float = 0.0


async def _probe_port(host: str, port: int, timeout: float, grab_banner: bool) -> PortState:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return PortState(port=port, open=False, service=TOP_PORTS.get(port))

    banner: str | None = None
    if grab_banner:
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=min(2.0, timeout))
            if data:
                banner = data.decode("latin-1", errors="replace").strip() or None
        except (asyncio.TimeoutError, OSError):
            pass
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except (asyncio.TimeoutError, OSError):
        pass
    return PortState(port=port, open=True, service=TOP_PORTS.get(port), banner=banner)


async def scan_ports(
    host: str,
    ports: list[int],
    *,
    timeout: float = 2.0,
    concurrency: int = 100,
    grab_banner: bool = False,
    limiter=None,
    connect_host: str | None = None,
) -> ScanResult:
    # Connect to connect_host (a pre-validated IP) when given, so every port hits the
    # address the SSRF guard checked — no per-connection re-resolution a rebinding
    # attacker could swap. `host` stays the display name.
    target = connect_host or host
    loop = asyncio.get_event_loop()
    start = loop.time()
    sem = asyncio.Semaphore(max(1, concurrency))

    async def bounded(p: int) -> PortState:
        async with sem:
            # Honour the shared outbound rate limit (the most intrusive tool
            # must respect MOONMCP_RATE_LIMIT like everything else).
            if limiter is not None:
                await limiter.acquire()
            return await _probe_port(target, p, timeout, grab_banner)

    states = await asyncio.gather(*(bounded(p) for p in ports))
    duration = (loop.time() - start) * 1000
    open_ports = sorted((s for s in states if s.open), key=lambda s: s.port)
    return ScanResult(host=host, open_ports=open_ports, scanned=len(ports), duration_ms=round(duration, 1))


def parse_ports(spec: str | None) -> list[int]:
    """Parse a port spec like ``"80,443,8000-8100"`` into a sorted unique list.

    ``None``/empty/``"top"`` returns the curated TOP_PORTS set.
    """

    if not spec or spec.strip().lower() in {"top", "default", "common"}:
        return sorted(TOP_PORTS)
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            try:
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                continue
            if lo_i > hi_i:
                lo_i, hi_i = hi_i, lo_i
            for p in range(max(1, lo_i), min(65535, hi_i) + 1):
                out.add(p)
        else:
            try:
                p = int(chunk)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                out.add(p)
    return sorted(out)
