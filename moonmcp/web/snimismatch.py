"""SNI / Host mismatch — the domain-fronting / SNI-bypass primitive, detection only.

A TLS-terminating edge often binds its **security policy** (an SNI-keyed WAF rule set, an mTLS
client-cert requirement, a CDN customer zone, geo/IP-reputation scoring) to the SNI the client
presented in the ClientHello — but then routes the actual HTTP **content** by the separately
encrypted, unauthenticated ``Host`` header. When those two layers disagree about identity, an
attacker never has to present the *real* target's SNI at all: connect with an unrelated decoy
hostname (or send no SNI whatsoever) and still ask for the real ``Host`` — if the edge serves the
same content, whatever protection was keyed to the SNI never saw this request as belonging to that
site.

This is the classic **domain-fronting** technique, applied as a WAF/CDN-security-bypass signal:
compare the baseline (SNI=Host=real target) against an alternate-SNI request (SNI=decoy or blank,
Host=real target); matching content proves the edge's routing does not depend on SNI matching Host,
so an SNI-bound security layer can be routed around by simply not presenting it. `vhost_probe`
already flags the reverse direction (SNI=real, Host=bogus, i.e. "SNI≠Host not enforced" as an
*internal-access* signal) — this module supplies the missing, attacker-relevant direction.
Detection only: two extra benign GETs over fresh connections, nothing exploited.

Sources: Fifield et al., "Blocking-resistant communication through domain fronting" (PETS 2015);
Bishop Fox / PortSwigger write-ups on CDN Host-vs-SNI confusion.
"""

from __future__ import annotations

import asyncio
import ssl

from ..pin import connect_host
from . import http2 as http2mod

# A syntactically valid but unrelated hostname — presented as the ClientHello SNI while the HTTP
# Host header still names the real target (the domain-fronting primitive).
DECOY_SNI = "moonsni-decoy.example"


def build_get(host_header: str, path: str) -> bytes:
    """A benign, complete HTTP/1.1 GET with ``Host: host_header`` on a fresh connection (pure)."""

    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host_header}",
        "Connection: close",
        "Accept: */*",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def content_matches(base_status: int | None, base_len: int, status: int | None, length: int,
                    jitter: int) -> bool:
    """Same status and body-length within the baseline's natural jitter == the edge served the
    SAME content regardless of which SNI was presented (pure)."""

    return (status is not None and base_status is not None and status == base_status
           and abs(length - base_len) <= jitter + 256)


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # SNI is deliberately mismatched vs Host — never validate
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def fetch_over_sni(host: str, port: int, *, sni: str, host_header: str, path: str,
                         timeout: float) -> tuple[int | None, int, str | None]:
    """One raw-socket GET over a TLS connection whose ClientHello SNI is *sni* (an empty string
    sends NO SNI extension at all — the documented ``server_hostname=''`` asyncio idiom) while the
    HTTP ``Host`` header is *host_header*. Returns ``(status, body_length, error)``."""

    request = build_get(host_header, path)
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host(host), port, ssl=_tls_context(),
                                    server_hostname=sni), timeout=timeout)
        writer.write(request)
        await writer.drain()
        raw = b""
        while len(raw) < 500_000:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                break
            raw += chunk
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return None, 0, f"{type(exc).__name__}: {exc}"
    finally:
        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass
    status, _headers = http2mod.parse_response(raw)
    parts = raw.split(b"\r\n\r\n", 1)
    body_len = len(parts[1]) if len(parts) > 1 else 0
    return status, body_len, None
