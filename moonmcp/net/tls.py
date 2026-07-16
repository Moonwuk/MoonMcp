"""TLS / X.509 certificate inspection using the standard-library ``ssl`` module.

Returns the peer certificate's subject, issuer, validity window, and — crucially
for recon — the Subject Alternative Names, which frequently leak sibling
hostnames worth adding to scope.
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import tempfile
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..pin import connect_host


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


def _decode_der_cert(der: bytes) -> dict:
    """Decode a DER certificate into the ``getpeercert()``-style dict WITHOUT trust
    verification. ``getpeercert()`` returns ``{}`` under ``CERT_NONE`` (CPython does
    not decode an unverified peer cert), so to inspect a cert regardless of trust we
    parse the raw DER ourselves via the stdlib decoder."""

    if not der:
        return {}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        tf = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        try:
            tf.write(pem)
            tf.close()
            return ssl._ssl._test_decode_cert(tf.name)  # type: ignore[attr-defined]
        finally:
            os.unlink(tf.name)
    except Exception:
        return {}


def _blocking_inspect(host: str, port: int, timeout: float, server_name: str | None) -> TlsResult:
    result = TlsResult(host=host, port=port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    der = b""
    try:
        with socket.create_connection((connect_host(host), port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name or host) as tls:
                result.connected = True
                result.version = tls.version()
                cipher = tls.cipher()
                result.cipher = cipher[0] if cipher else None
                # getpeercert() is {} under CERT_NONE — grab the DER and decode it.
                der = tls.getpeercert(binary_form=True) or b""
    except TimeoutError:
        result.error = "connection timed out"
        return result
    except (ssl.SSLError, socket.gaierror, ConnectionError, OSError) as exc:
        result.error = str(exc)
        return result

    cert = _decode_der_cert(der)
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


def origin_hostname_hints(target_host: str, sans: list[str]) -> list[str]:
    """Hostnames on a DEFAULT / bogus-SNI certificate that name a host OTHER than the
    target (and not a parent/child of it) — a sibling tenant on the same edge or the
    origin's own hostname, i.e. an origin-exposure / lateral-surface lead. Wildcards
    are unwrapped; duplicates and same-org sub/parent domains are dropped."""

    t = (target_host or "").lower().strip().lstrip(".")
    out: list[str] = []
    for s in sans:
        h = (s or "").lower().strip().lstrip("*.").lstrip(".")
        if not h or h == t or (t and (t.endswith("." + h) or h.endswith("." + t))):
            continue
        if h not in out:
            out.append(h)
    return out


async def inspect_certificate(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    server_name: str | None = None,
) -> TlsResult:
    return await asyncio.to_thread(_blocking_inspect, host, port, timeout, server_name)


# --- TLS profiling / fingerprinting -------------------------------------
_TLS_VERSIONS = [
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]


@dataclass
class TlsProfile:
    host: str
    port: int
    supported_versions: list[str] = field(default_factory=list)
    cipher_by_version: dict[str, str] = field(default_factory=dict)
    alpn: list[str] = field(default_factory=list)
    http2: bool = False
    weak_versions: list[str] = field(default_factory=list)
    error: str | None = None


def _try_version(host: str, port: int, version, timeout: float) -> tuple[bool, str | None]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            # Pinning TLS 1.0/1.1 warns; we deliberately probe for them.
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
            # OpenSSL 3.x defaults to SECLEVEL 2, which refuses to OFFER TLS 1.0/1.1 and
            # their ciphers — so the probe could never negotiate the very legacy versions
            # it is meant to flag as weak (weak_versions stayed empty against a genuinely
            # weak server). Lower the security level for the legacy probes only.
            if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                try:
                    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
    except (ValueError, OSError):
        return False, None
    try:
        with socket.create_connection((connect_host(host), port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                c = tls.cipher()
                return True, (c[0] if c else None)
    except (ssl.SSLError, OSError, ValueError):
        return False, None


def _probe_alpn(host: str, port: int, timeout: float) -> list[str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        return []
    try:
        with socket.create_connection((connect_host(host), port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                selected = tls.selected_alpn_protocol()
                return [selected] if selected else []
    except (ssl.SSLError, OSError):
        return []


def _blocking_profile(host: str, port: int, timeout: float) -> TlsProfile:
    profile = TlsProfile(host=host, port=port)
    any_ok = False
    for name, version in _TLS_VERSIONS:
        if version is None:
            continue
        ok, cipher = _try_version(host, port, version, timeout)
        if ok:
            any_ok = True
            profile.supported_versions.append(name)
            if cipher:
                profile.cipher_by_version[name] = cipher
            if name in ("TLSv1.0", "TLSv1.1"):
                profile.weak_versions.append(name)
    if not any_ok:
        profile.error = "no TLS handshake succeeded"
        return profile
    profile.alpn = _probe_alpn(host, port, timeout)
    profile.http2 = "h2" in profile.alpn
    return profile


async def probe_tls_profile(host: str, port: int = 443, timeout: float = 10.0) -> TlsProfile:
    return await asyncio.to_thread(_blocking_profile, host, port, timeout)
