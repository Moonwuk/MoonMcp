"""TLS / X.509 certificate inspection using the standard-library ``ssl`` module.

Returns the peer certificate's subject, issuer, validity window, and — crucially
for recon — the Subject Alternative Names, which frequently leak sibling
hostnames worth adding to scope.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class TlsResult:
    host: str
    port: int
    connected: bool = False
    error: str | None = None
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    subject_alt_names: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    expired: bool | None = None
    version: str | None = None
    cipher: str | None = None
    serial_number: str | None = None


def _flatten_name(rdn_seq) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in rdn_seq or ():
        for key, value in rdn:
            out[key] = value
    return out


def _parse_cert_date(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _blocking_inspect(host: str, port: int, timeout: float, server_name: str | None) -> TlsResult:
    result = TlsResult(host=host, port=port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name or host) as tls:
                result.connected = True
                result.version = tls.version()
                cipher = tls.cipher()
                result.cipher = cipher[0] if cipher else None
                cert = tls.getpeercert()
    except TimeoutError:
        result.error = "connection timed out"
        return result
    except (ssl.SSLError, socket.gaierror, ConnectionError, OSError) as exc:
        result.error = str(exc)
        return result

    if not cert:
        result.error = "no certificate presented"
        return result

    result.subject = _flatten_name(cert.get("subject"))
    result.issuer = _flatten_name(cert.get("issuer"))
    result.subject_alt_names = [v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]
    result.not_before = cert.get("notBefore")
    result.not_after = cert.get("notAfter")
    result.serial_number = cert.get("serialNumber")

    expires = _parse_cert_date(cert.get("notAfter", ""))
    if expires is not None:
        now = datetime.now(timezone.utc)
        result.days_until_expiry = (expires - now).days
        result.expired = expires < now
    return result


async def inspect_certificate(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    server_name: str | None = None,
) -> TlsResult:
    return await asyncio.to_thread(_blocking_inspect, host, port, timeout, server_name)
