"""HTTP request-smuggling / desync **indicator** probe (detection only).

This does NOT attempt a smuggling attack.  Every request it sends is a single,
**complete, well-formed** HTTP/1.1 message on its own fresh connection, so no
partial request is ever left to poison a shared connection.  It simply observes
how the server handles ambiguous framing (both ``Content-Length`` and
``Transfer-Encoding``, and obfuscated ``Transfer-Encoding`` headers) and reports
that as a risk *indicator* — always confirm with a dedicated tool under explicit
authorisation before reporting a finding.

Intrusive: the server gates it behind ``MOONMCP_ALLOW_INTRUSIVE`` + scope.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class DesyncResult:
    url: str
    baseline_status: int | None = None
    server: str | None = None
    probes: dict[str, int | None] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)
    risk: str = "low"
    note: str = ("Indicators only — NOT a confirmed vulnerability. Verify manually "
                 "with a dedicated request-smuggling tool under authorisation.")
    error: str | None = None


def _status_of(data: bytes) -> tuple[int | None, str | None]:
    try:
        line, _, rest = data.partition(b"\r\n")
        parts = line.split(b" ", 2)
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        server = None
        for hl in rest.split(b"\r\n"):
            if hl.lower().startswith(b"server:"):
                server = hl.split(b":", 1)[1].strip().decode("latin-1", "replace")
                break
        return status, server
    except (ValueError, IndexError):
        return None, None


async def _raw_request(host: str, port: int, tls: bool, raw: bytes, timeout: float) -> bytes | None:
    ssl_ctx = None
    if tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        fut = asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host if tls else None)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, ssl.SSLError, OSError):
        return None
    try:
        writer.write(raw)
        await writer.drain()
        return await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except (asyncio.TimeoutError, OSError):
            pass


def _req(host: str, path: str, extra_headers: str = "", body: str = "") -> bytes:
    head = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MoonMCP\r\n"
            f"Accept: */*\r\nConnection: close\r\n{extra_headers}\r\n{body}")
    return head.encode("latin-1")


async def probe_desync(url: str, *, timeout: float = 12.0) -> DesyncResult:
    parts = urlsplit(url if "://" in url else f"https://{url}")
    tls = parts.scheme != "http"
    host = parts.hostname or ""
    port = parts.port or (443 if tls else 80)
    path = parts.path or "/"
    result = DesyncResult(url=url)

    base = await _raw_request(host, port, tls, _req(host, path), timeout)
    if base is None:
        result.error = "unreachable"
        return result
    result.baseline_status, result.server = _status_of(base)

    # A complete, empty chunked body advertised with BOTH CL and TE. Both parsers
    # read exactly this message, so nothing is left dangling.
    complete_chunked = "0\r\n\r\n"
    clte = _req(host, path,
                extra_headers=f"Content-Length: {len(complete_chunked)}\r\nTransfer-Encoding: chunked\r\n",
                body=complete_chunked)
    r = await _raw_request(host, port, tls, clte, timeout)
    result.probes["cl.te-dual"] = _status_of(r)[0] if r else None

    # Obfuscated Transfer-Encoding variants (each a complete message).
    variants = {
        "te-space-before-colon": "Transfer-Encoding : chunked\r\n",
        "te-tab": "Transfer-Encoding:\tchunked\r\n",
        "te-nameprefix": "X: x\r\nTransfer-Encoding: chunked\r\n",
    }
    for name, hdr in variants.items():
        rr = await _raw_request(host, port, tls, _req(host, path, extra_headers=hdr, body=complete_chunked), timeout)
        result.probes[name] = _status_of(rr)[0] if rr else None

    # Interpretation (indicators only).
    base_ok = result.baseline_status is not None and result.baseline_status < 400
    dual = result.probes.get("cl.te-dual")
    if dual is not None and dual < 400 and base_ok:
        result.indicators.append("Server accepted a request with both Content-Length and "
                                 "Transfer-Encoding (RFC says reject) — review for CL.TE/TE.CL desync")
    accepted_obf = [n for n in variants if (result.probes.get(n) is not None and result.probes[n] < 400)]
    if accepted_obf:
        result.indicators.append(f"Obfuscated Transfer-Encoding accepted: {', '.join(accepted_obf)}")
    result.risk = "review" if result.indicators else "low"
    return result
