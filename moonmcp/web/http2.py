"""HTTP/2 surface probe — h2c cleartext-upgrade / smuggling + DoS-CVE advisory, detection only.

Two HTTP/2 exposures a plain web scan misses:

* **H2C smuggling (the active, confirmable one).** If the edge honours an ``Upgrade: h2c``
  (cleartext HTTP/2) request with a ``101 Switching Protocols``, and a reverse proxy fronts the
  origin, an attacker can tunnel requests over the upgraded h2c stream that the proxy no longer
  inspects — bypassing its path/method access controls (Bishop Fox "h2c smuggling"). The tell is
  a benign ``101`` to the upgrade handshake; we never smuggle a real request past the ACL — that
  confirmation is Strix's job.
* **HTTP/2 DoS exposure (informational).** Any host that negotiates ``h2`` is protocol-level
  exposed to Rapid Reset (CVE-2023-44487) and, on affected stacks, the CONTINUATION flood
  (CVE-2024-27316) — neither can be *confirmed* without actually flooding, which we never do, so
  it is reported as an advisory to verify the patch/mitigation, not a finding.

ALPN ``h2`` detection reuses the TLS layer; the h2c handshake is one benign upgrade request over
the same connection type as the target (TLS for https, cleartext for http).
"""

from __future__ import annotations

import asyncio
import base64
import ssl

from ..pin import connect_host

# A minimal valid HTTP2-Settings payload (SETTINGS_MAX_CONCURRENT_STREAMS = 100), base64url — the
# h2c upgrade request must carry one (RFC 7540 §3.2.1).
_H2_SETTINGS = base64.urlsafe_b64encode(b"\x00\x03\x00\x00\x00\x64").rstrip(b"=").decode()

# HTTP/2 DoS CVEs — advisory only (can't be confirmed without flooding, which we never do).
DOS_CVES = (
    {"id": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset", "note": "protocol-level; any HTTP/2 server "
     "without stream-cancel rate limiting", "kev": True},
    {"id": "CVE-2024-27316", "name": "HTTP/2 CONTINUATION flood", "note": "Apache httpd / nghttp2 / "
     "Node and other stacks that buffer CONTINUATION frames", "kev": False},
)


def build_h2c_upgrade(host_header: str, path: str) -> bytes:
    """The benign HTTP/1.1 request that offers an upgrade to cleartext HTTP/2 (pure)."""

    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host_header}",
        "Connection: Upgrade, HTTP2-Settings",
        "Upgrade: h2c",
        f"HTTP2-Settings: {_H2_SETTINGS}",
        "Accept: */*",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def parse_response(raw: bytes) -> tuple[int | None, dict[str, str]]:
    """Parse the HTTP/1.1 status line + headers from a raw response head (pure)."""

    text = (raw or b"").decode("latin-1", "replace")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    status = None
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(None, 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers


def is_h2c_upgrade(status: int | None, headers: dict[str, str]) -> bool:
    """Did the edge switch to cleartext HTTP/2 — ``101`` + ``Upgrade: h2c``? (pure)"""

    return status == 101 and "h2c" in (headers.get("upgrade", "").lower())


def assess(alpn: list[str] | None, h2c_status: int | None, h2c_headers: dict[str, str],
           server: str | None) -> dict:
    """Combine the ALPN result + the h2c handshake outcome into findings + a verdict (pure)."""

    http2_alpn = "h2" in (alpn or [])
    h2c = is_h2c_upgrade(h2c_status, h2c_headers)
    findings: list[dict] = []
    if h2c:
        findings.append({
            "kind": "h2c_upgrade", "severity": "medium",
            "detail": ("the edge accepted `Upgrade: h2c` (101 Switching Protocols) — cleartext HTTP/2 "
                       "upgrade is honoured. If a reverse proxy fronts this host, requests can be "
                       "tunnelled over the h2c stream to bypass its path/method ACLs (H2C smuggling). "
                       "Confirm the ACL bypass via Strix — no request was smuggled here.")})
    advisory = [dict(c) for c in DOS_CVES] if (http2_alpn or h2c) else []
    verdict = ("h2c_smuggling_candidate" if h2c
               else "http2_enabled" if http2_alpn else "no_http2")
    return {"alpn": alpn or [], "http2_alpn": http2_alpn, "h2c_upgrade": h2c,
            "server": server, "findings": findings, "dos_advisory": advisory, "verdict": verdict}


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # recon posture: a bad cert must not abort detection
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _h2c_handshake(host: str, port: int, tls: bool, path: str, host_header: str,
                         timeout: float) -> tuple[int | None, dict[str, str]]:
    """One benign Upgrade: h2c request; read the response head, return (status, headers)."""

    request = build_h2c_upgrade(host_header, path)
    ssl_ctx = _tls_context() if tls else None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host(host), port, ssl=ssl_ctx,
                                    server_hostname=host if tls else None), timeout=timeout)
        writer.write(request)
        await writer.drain()
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 8192:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            raw += chunk
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None, {}
    finally:
        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass
    return parse_response(raw)


async def probe_http2(host: str, port: int, tls: bool, path: str, *, host_header: str,
                      timeout: float = 8.0, alpn: list[str] | None = None,
                      server: str | None = None) -> dict:
    """Detection-only HTTP/2 probe: the ALPN result (reused from the TLS layer via *alpn*) plus a
    benign h2c-upgrade handshake, assessed into findings + a DoS advisory."""

    status, headers = await _h2c_handshake(host, port, tls, path, host_header, timeout)
    return assess(alpn, status, headers, server)
