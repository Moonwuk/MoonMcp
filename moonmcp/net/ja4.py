"""JA4+ server & certificate fingerprinting (FoxIO JA4S / JA4X).

The successor family to JARM/JA3. JARM folds ten crafted hellos into a 62-char fuzzy
hash; JA4+ instead reads the standard, structured fields of a single exchange, so a
JA4S/JA4X is directly comparable to the public FoxIO databases (server-stack, CDN, and
certificate-issuance attribution — and known-C2/malware infra correlation).

This module implements the two variants that fingerprint a **target server** (a scanner
connecting outward):

* **JA4S** — the server's TLS response fingerprint, parsed from its ServerHello: the
  negotiated version, the chosen cipher, and the ordered list of ServerHello extensions
  (+ any chosen ALPN). We send one standard TLS 1.3 ClientHello (reusing the JARM
  ClientHello builder) and parse the raw ServerHello — the stdlib ``ssl`` module never
  exposes the extension order we need.
* **JA4X** — the X.509 certificate fingerprint: truncated SHA-256 over the Issuer RDN
  OIDs, the Subject RDN OIDs, and the extension OIDs (each OID in DER-hex, in certificate
  order). Computed from the DER the TLS handshake already yields.

Out of scope (documented, not a target-attribution signal from a client scanner): **JA4**
and **JA4H** fingerprint the *client* / its *HTTP request* (they'd fingerprint MoonMCP
itself); **JA4T** needs the peer's TCP SYN-ACK options, which a pure-Python socket cannot
read without raw-socket/root access. QUIC (transport ``q``) is likewise not probed — TCP
(``t``) only.

Spec: https://github.com/FoxIO-LLC/ja4 (JA4/JA4S BSD-3; JA4X under FoxIO License 1.1).
This is an independent implementation of the published algorithm.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from dataclasses import dataclass, field

from ..pin import connect_host
from .jarm import build_client_hello

# A single, fixed, standards-representative TLS 1.3 ClientHello (all ciphers forward, no
# GREASE, standard ALPN incl. h2/http-1.1, supported_versions with 1.3) — so the JA4S we
# derive is reproducible across scans and comparable target-to-target.
_JA4S_CLIENT_HELLO_SPEC: list = ["", 443, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE",
                                 "APLN", "1.3_SUPPORT", "FORWARD"]

_VERSION_MAP = {
    b"\x03\x04": "13", b"\x03\x03": "12", b"\x03\x02": "11", b"\x03\x01": "10",
    b"\x03\x00": "s3", b"\x02\x00": "s2", b"\x01\x00": "s1",
}


def _version_code(ver: bytes) -> str:
    return _VERSION_MAP.get(bytes(ver), "00")


def _alpn_code(alpn: str) -> str:
    """First+last char of the chosen ALPN (``h2`` → ``h2``, ``http/1.1`` → ``h1``);
    ``00`` when there is none or the ends aren't alphanumeric."""

    if not alpn:
        return "00"
    a, b = alpn[0], alpn[-1]
    return a + b if a.isalnum() and b.isalnum() else "00"


def parse_server_hello(data: bytes) -> dict | None:
    """Parse a raw TLS ServerHello record into the fields JA4S needs:
    ``{version, cipher, ext_types, alpn}`` (pure). Returns ``None`` if *data* is not a
    ServerHello (e.g. an alert, or a truncated/garbage response)."""

    # TLS record: [0]=0x16 handshake, [3:5]=len, [5]=0x02 ServerHello, [9:11]=legacy_ver,
    # [11:43]=random, [43]=session_id length.
    if len(data) < 44 or data[0] != 0x16 or data[5] != 0x02:
        return None
    try:
        legacy_ver = data[9:11]
        sid_len = data[43]
        off = 44 + sid_len
        cipher = data[off:off + 2]
        off += 3  # cipher (2) + compression method (1)
        version = legacy_ver
        ext_types: list[str] = []
        alpn = ""
        if off + 2 <= len(data):
            ext_total = int.from_bytes(data[off:off + 2], "big")
            off += 2
            end = min(off + ext_total, len(data))
            while off + 4 <= end:
                etype = data[off:off + 2]
                elen = int.from_bytes(data[off + 2:off + 4], "big")
                edata = data[off + 4:off + 4 + elen]
                ext_types.append(etype.hex())
                if etype == b"\x00\x2b" and len(edata) >= 2:      # supported_versions (chosen)
                    version = edata[:2]
                elif etype == b"\x00\x10" and len(edata) >= 3:    # ALPN (chosen protocol)
                    plen = edata[2]
                    alpn = edata[3:3 + plen].decode("latin-1", "replace")
                off += 4 + elen
        return {"version": _version_code(version), "cipher": cipher.hex(),
                "ext_types": ext_types, "alpn": alpn}
    except (IndexError, ValueError):
        return None


def ja4s_string(parsed: dict, *, transport: str = "t") -> str:
    """Assemble the JA4S string from :func:`parse_server_hello` output (pure).

    ``<t|q><ver><nn-ext><alpn>_<cipher>_<sha256(ext types, in order)[:12]>``,
    e.g. ``t130200_1301_234ea6891581``."""

    ext_types = parsed["ext_types"]
    a = f"{transport}{parsed['version']}{min(len(ext_types), 99):02d}{_alpn_code(parsed['alpn'])}"
    b = (parsed["cipher"] or "0000").lower()
    c = (hashlib.sha256(",".join(ext_types).encode()).hexdigest()[:12]
         if ext_types else "0" * 12)
    return f"{a}_{b}_{c}"


def _oid_to_hex(dotted: str) -> str:
    """DER-encode a dotted OID to its body hex (``2.5.4.6`` → ``550406``) — JA4X hashes
    the OIDs in this hex form (pure)."""

    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        if n < 128:
            body.append(n)
            continue
        stack = [n & 0x7F]
        n >>= 7
        while n:
            stack.append((n & 0x7F) | 0x80)
            n >>= 7
        body.extend(reversed(stack))
    return bytes(body).hex()


def _ja4x_segment(oids_hex: list[str]) -> str:
    return hashlib.sha256(",".join(oids_hex).encode()).hexdigest()[:12] if oids_hex else "0" * 12


def ja4x_from_der(der: bytes) -> dict | None:
    """JA4X over the certificate DER: ``<issuer>_<subject>_<extensions>``, each a
    truncated SHA-256 of the OID list (DER-hex, in cert order). Returns the fingerprint
    plus the raw OID lists for verification, or ``None`` if the cert can't be parsed."""

    try:
        from cryptography import x509
    except ImportError:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
        issuer = [_oid_to_hex(a.oid.dotted_string) for a in cert.issuer]
        subject = [_oid_to_hex(a.oid.dotted_string) for a in cert.subject]
        exts = [_oid_to_hex(e.oid.dotted_string) for e in cert.extensions]
    except Exception:  # noqa: BLE001 - a malformed cert must never crash the probe
        return None
    ja4x = f"{_ja4x_segment(issuer)}_{_ja4x_segment(subject)}_{_ja4x_segment(exts)}"
    return {"ja4x": ja4x, "issuer_oids": issuer, "subject_oids": subject, "extension_oids": exts}


@dataclass
class Ja4Result:
    host: str
    port: int
    ja4s: str | None = None
    ja4s_detail: dict | None = None
    ja4x: str | None = None
    ja4x_detail: dict | None = None
    error: str | None = None
    notes: list[str] = field(default_factory=list)


async def _read_server_hello(host: str, port: int, timeout: float) -> bytes | None:
    spec = list(_JA4S_CLIENT_HELLO_SPEC)
    spec[0], spec[1] = host, port
    try:
        fut = asyncio.open_connection(connect_host(host), port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        writer.write(build_client_hello(spec))   # SNI is inside the crafted hello
        await writer.drain()
        return bytes(await asyncio.wait_for(reader.read(4096), timeout=timeout))
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except (asyncio.TimeoutError, OSError):
            pass


def _get_cert_der(host: str, port: int, timeout: float) -> bytes | None:
    import socket
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((connect_host(host), port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True) or None
    except (OSError, ssl.SSLError, ValueError):
        return None


async def compute_ja4(host: str, port: int = 443, timeout: float = 10.0) -> Ja4Result:
    """Probe *host:port* for its JA4S (server TLS) and JA4X (certificate) fingerprints."""

    res = Ja4Result(host=host, port=port)
    sh = await _read_server_hello(host, port, timeout)
    if sh:
        parsed = parse_server_hello(sh)
        if parsed:
            res.ja4s = ja4s_string(parsed)
            res.ja4s_detail = parsed
        else:
            res.notes.append("server did not return a parseable ServerHello (no JA4S)")
    else:
        res.notes.append("no ServerHello (TLS unreachable on this port) — no JA4S")

    der = await asyncio.to_thread(_get_cert_der, host, port, timeout)
    if der:
        jx = ja4x_from_der(der)
        if jx:
            res.ja4x = jx.pop("ja4x")
            res.ja4x_detail = jx
    else:
        res.notes.append("no certificate retrieved — no JA4X")

    if res.ja4s is None and res.ja4x is None and not res.error:
        res.error = "no TLS fingerprint could be derived (host unreachable or not TLS)"
    return res
