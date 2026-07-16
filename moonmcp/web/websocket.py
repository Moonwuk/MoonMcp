"""WebSocket detection probe — RFC 6455 handshake + Cross-Site WebSocket Hijacking.

Most scanners stop at HTTP and never touch the WebSocket surface, where real-time
BOLA, message injection and **Cross-Site WebSocket Hijacking (CSWSH)** live. This
module speaks the WebSocket handshake by hand (stdlib only — no `websockets`
dependency) and reports **detection signals**, never exploitation:

* **Endpoint confirmation** — does the URL upgrade to WebSocket (HTTP 101 +
  a valid ``Sec-WebSocket-Accept``)?
* **CSWSH / origin validation** — the flagship check: repeat the handshake with a
  *foreign* ``Origin``. If the server still returns 101, it does not validate the
  Origin — a cookie-authenticated socket is then hijackable cross-site. This is a
  **lead** (confirm whether the socket carries authenticated actions), routed to
  `promote_lead` / Strix for a PoC, not weaponised here.
* **Optional benign echo** — opt-in (`probe_message`): send one clearly-marked
  benign text frame and see if it is reflected (a message-injection surface).

Every client frame is masked per spec; nothing destructive is ever sent, and the
handshake itself is as benign as an HTTP GET with upgrade headers.

Sources: RFC 6455 · https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
import struct
from dataclasses import dataclass, field

from ..pin import connect_host

# RFC 6455 handshake GUID, concatenated with the client key to derive the accept.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# The foreign Origin used for the CSWSH check — a domain we obviously don't control
# and that is not the target, so acceptance proves the Origin isn't validated.
_FOREIGN_ORIGIN = "https://moonmcp-cswsh-probe.example"


def accept_value(key: str) -> str:
    """Compute ``Sec-WebSocket-Accept`` = base64(sha1(key + GUID)) (RFC 6455)."""

    digest = hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()  # noqa: S324 - spec-mandated
    return base64.b64encode(digest).decode("ascii")


def new_key() -> str:
    """A fresh base64 ``Sec-WebSocket-Key`` (16 random bytes, per spec)."""

    return base64.b64encode(os.urandom(16)).decode("ascii")


def build_handshake(host_header: str, path: str, key: str, *, origin: str | None = None,
                    subprotocols: str | None = None,
                    extra_headers: dict[str, str] | None = None) -> bytes:
    """Build the raw HTTP/1.1 Upgrade request that opens a WebSocket (pure)."""

    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host_header}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        lines.append(f"Origin: {origin}")
    if subprotocols:
        lines.append(f"Sec-WebSocket-Protocol: {subprotocols}")
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def parse_handshake_response(raw: bytes) -> dict:
    """Parse the server's handshake response into ``{status, headers, ...}`` (pure)."""

    text = raw.decode("latin-1", errors="replace")
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
    return {"status": status, "headers": headers,
            "accept": headers.get("sec-websocket-accept"),
            "subprotocol": headers.get("sec-websocket-protocol"),
            "upgrade": (headers.get("upgrade") or "").lower()}


def handshake_ok(parsed: dict, key: str) -> bool:
    """A valid WebSocket upgrade: 101 + Upgrade: websocket + a correct accept."""

    return (parsed.get("status") == 101
            and "websocket" in parsed.get("upgrade", "")
            and parsed.get("accept") == accept_value(key))


def encode_text_frame(payload: str) -> bytes:
    """Encode a masked client text frame (FIN=1, opcode=0x1) — client frames must
    be masked per RFC 6455 §5.1 (pure)."""

    data = payload.encode("utf-8")
    header = bytearray([0x81])  # FIN + text opcode
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += struct.pack("!H", n)
    else:
        header.append(0x80 | 127)
        header += struct.pack("!Q", n)
    mask = os.urandom(4)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return bytes(header) + masked


def decode_frame(data: bytes) -> tuple[int | None, bytes, int]:
    """Decode one server frame → ``(opcode, payload, bytes_consumed)``. Returns
    ``(None, b"", 0)`` if ``data`` doesn't yet hold a whole frame (pure). Server
    frames are unmasked per spec."""

    if len(data) < 2:
        return None, b"", 0
    opcode = data[0] & 0x0F
    masked = bool(data[1] & 0x80)
    length = data[1] & 0x7F
    idx = 2
    if length == 126:
        if len(data) < idx + 2:
            return None, b"", 0
        length = struct.unpack("!H", data[idx:idx + 2])[0]
        idx += 2
    elif length == 127:
        if len(data) < idx + 8:
            return None, b"", 0
        length = struct.unpack("!Q", data[idx:idx + 8])[0]
        idx += 8
    mask = b""
    if masked:
        if len(data) < idx + 4:
            return None, b"", 0
        mask = data[idx:idx + 4]
        idx += 4
    if len(data) < idx + length:
        return None, b"", 0
    payload = data[idx:idx + length]
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload, idx + length


@dataclass
class WsResult:
    target: str
    url: str
    is_websocket: bool = False
    handshake: dict = field(default_factory=dict)
    origin_check: dict = field(default_factory=dict)
    echo: dict | None = None
    leads: list[dict] = field(default_factory=list)
    review: list[str] = field(default_factory=list)
    error: str | None = None


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # recon posture: a bad/self-signed cert must
    ctx.verify_mode = ssl.CERT_NONE     # not abort detection of the WS surface
    return ctx


def split_ws_url(url: str) -> tuple[str, int, str, bool]:
    """``ws(s)://host:port/path`` (or http(s)/bare host) → (host, port, path, tls)."""

    from urllib.parse import urlsplit

    raw = (url or "").strip()
    if "://" not in raw:
        raw = "wss://" + raw
    p = urlsplit(raw)
    scheme = (p.scheme or "wss").lower()
    tls = scheme in ("wss", "https")
    host = p.hostname or ""
    try:
        port = p.port or (443 if tls else 80)
    except ValueError:
        port = 443 if tls else 80
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return host, port, path, tls


async def _handshake(host: str, port: int, tls: bool, path: str, host_header: str,
                     timeout: float, *, origin: str | None,
                     subprotocols: str | None) -> dict:
    """Open one connection, do the WS handshake, close, return the parsed result.

    ``ok`` is True only for a spec-valid upgrade (101 + matching accept)."""

    key = new_key()
    request = build_handshake(host_header, path, key, origin=origin, subprotocols=subprotocols)
    ssl_ctx = _tls_context() if tls else None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host(host), port, ssl=ssl_ctx,
                                    server_hostname=host if tls else None),
            timeout=timeout)
        writer.write(request)
        await writer.drain()
        # Read until the end of the header block (or EOF) — a single read() can return
        # just the 101 line when the Sec-WebSocket-* headers arrive in a later TCP
        # segment, which would misparse a real WS endpoint as non-WS.
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 8192:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            raw += chunk
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return {"ok": False, "status": None, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass
    parsed = parse_handshake_response(raw)
    parsed["ok"] = handshake_ok(parsed, key)
    return parsed


async def _echo(host: str, port: int, tls: bool, path: str, host_header: str,
                timeout: float, origin: str | None, marker: str) -> dict:
    """Opt-in: handshake, send ONE benign marked text frame, read one frame back,
    report whether the marker was reflected. Never sent unless the caller asks."""

    key = new_key()
    request = build_handshake(host_header, path, key, origin=origin)
    ssl_ctx = _tls_context() if tls else None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host(host), port, ssl=ssl_ctx,
                                    server_hostname=host if tls else None),
            timeout=timeout)
        writer.write(request)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not handshake_ok(parse_handshake_response(resp), key):
            return {"sent": marker, "received": None, "reflected": False,
                    "note": "handshake failed; no frame sent"}
        # split off any bytes the server pipelined after the handshake header
        tail = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
        writer.write(encode_text_frame(marker))
        await writer.drain()
        buf = bytearray(tail)
        received = None
        for _ in range(4):
            opcode, payload, consumed = decode_frame(bytes(buf))
            if consumed:
                del buf[:consumed]
                if opcode in (0x1, 0x2):  # text/binary
                    received = payload.decode("utf-8", errors="replace")
                    break
                continue
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            buf += chunk
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return {"sent": marker, "received": None, "reflected": False,
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass
    return {"sent": marker, "received": received,
            "reflected": bool(received and marker in received)}


async def probe_websocket(url: str, *, host: str, port: int, path: str, tls: bool,
                          timeout: float = 8.0, probe_message: bool = False,
                          subprotocol: str | None = None) -> WsResult:
    """Detection-only WebSocket probe: confirm the endpoint, then test whether a
    foreign Origin is accepted (CSWSH). ``host``/``port``/``path``/``tls`` are the
    already-scoped connection target."""

    res = WsResult(target=url, url=url)
    port_sfx = "" if (port == (443 if tls else 80)) else f":{port}"
    host_header = f"{host}{port_sfx}"
    own_scheme = "https" if tls else "http"
    own_origin = f"{own_scheme}://{host}{port_sfx}"

    legit = await _handshake(host, port, tls, path, host_header, timeout,
                             origin=own_origin, subprotocols=subprotocol)
    res.handshake = {"status": legit.get("status"), "accept_valid": legit.get("ok", False),
                     "subprotocol": legit.get("subprotocol")}
    if legit.get("error"):
        res.handshake["error"] = legit["error"]
    if not legit.get("ok"):
        res.is_websocket = False
        res.review.append(
            "No valid WebSocket upgrade (need HTTP 101 + a correct Sec-WebSocket-Accept). "
            f"Server returned status {legit.get('status')}. Not a WebSocket endpoint, or "
            "the path/subprotocol is wrong.")
        return res

    res.is_websocket = True
    # CSWSH: does a FOREIGN Origin still get a 101? (origin not validated)
    foreign = await _handshake(host, port, tls, path, host_header, timeout,
                               origin=_FOREIGN_ORIGIN, subprotocols=subprotocol)
    foreign_accepted = foreign.get("ok", False)
    res.origin_check = {"legit_origin": own_origin, "legit_status": legit.get("status"),
                        "foreign_origin": _FOREIGN_ORIGIN,
                        "foreign_status": foreign.get("status"),
                        "foreign_accepted": foreign_accepted}
    if foreign_accepted:
        res.leads.append({
            "kind": "cswsh", "severity": "medium",
            "detail": (f"WebSocket at {url} accepted a handshake from a foreign Origin "
                       f"({_FOREIGN_ORIGIN}) — the server does not validate Origin. If the "
                       "socket is authenticated by cookies, it is hijackable cross-site "
                       "(Cross-Site WebSocket Hijacking).")})
        res.review.append(
            "CSWSH lead: foreign Origin accepted. CONFIRM by checking whether the socket "
            "authenticates via cookies AND carries sensitive reads/actions — if so it is a "
            "real CSWSH (route via promote_lead / Strix for a PoC). If the socket is "
            "unauthenticated or token-in-message, Origin acceptance is expected — not a bug.")
    else:
        res.review.append(
            f"Origin validated (foreign Origin got status {foreign.get('status')}). No CSWSH.")

    if probe_message:
        res.echo = await _echo(host, port, tls, path, host_header, timeout,
                               own_origin, "MoonMCP-ws-probe-7f3a")
        if res.echo.get("reflected"):
            res.leads.append({
                "kind": "message_reflection", "severity": "info",
                "detail": ("The WebSocket echoed our benign marker back — a reflection / "
                           "message-processing surface. Probe for injection via promote_lead / Strix.")})
            res.review.append("Echo: marker reflected — message-processing surface present.")
    return res

