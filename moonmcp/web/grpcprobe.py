"""gRPC / gRPC-Web detection probe — endpoint fingerprint + reflection / health exposure.

Most HTTP scanners never touch gRPC: it is POST-only, binary-framed, and usually HTTP/2.
gRPC-Web, however, rides plain HTTP/1.1 (Envoy's ``grpc_web`` filter, ``grpc-web`` JS clients,
Connect), so a benign gRPC-Web call is enough to (a) confirm a host speaks gRPC and (b) surface
two common misconfigurations without any exploitation:

* **Server Reflection exposed** — ``grpc.reflection.v1alpha/v1.ServerReflection`` lets anyone
  enumerate every service, method and message *without the .proto*. Enabled in production it is
  a schema-disclosure / attack-surface leak. A benign ``ListServices`` request that comes back
  ``grpc-status: 0`` (often with the service list itself) confirms it; ``UNIMPLEMENTED`` (12) /
  ``NOT_FOUND`` (5) means it is off.
* **Standard Health service exposed** — ``grpc.health.v1.Health/Check`` answering unauthenticated
  is an information leak (liveness of named sub-services).

The wire format is the gRPC-Web length-prefixed message frame — ``[1-byte flag][4-byte BE
length][payload]`` — with a trailing *trailer frame* (flag ``0x80``) carrying ``grpc-status``.
This module builds the benign requests and parses the frames + a minimal protobuf reader to
read back leaked service names; it sends **nothing executable** and reads only reflection /
health, which are metadata by design. Weaponizing a discovered method → Strix.

Sources: github.com/grpc/grpc/blob/master/doc/server-reflection.md ·
github.com/grpc/grpc-web (framing) · grpc.health.v1 · grpc.io status codes.
"""

from __future__ import annotations

import base64
import re
import struct

# Well-known service/method paths (the RPC path is ``/<service>/<method>``).
REFLECTION_V1ALPHA = "grpc.reflection.v1alpha.ServerReflection"
REFLECTION_V1 = "grpc.reflection.v1.ServerReflection"
REFLECTION_METHOD = "ServerReflectionInfo"
HEALTH_SERVICE = "grpc.health.v1.Health"
HEALTH_METHOD = "Check"
# A service we invent so a plain fingerprint call is guaranteed UNIMPLEMENTED on a real server.
PROBE_SERVICE = "moonmcp.grpcprobe.v1.MoonProbe"
PROBE_METHOD = "Ping"

CONTENT_TYPE = "application/grpc-web+proto"
REQUEST_HEADERS = {
    "content-type": CONTENT_TYPE,
    "accept": CONTENT_TYPE,
    "x-grpc-web": "1",
    "x-user-agent": "grpc-web-javascript/0.1",
}

# gRPC status codes we name in output (grpc.io/docs/guides/status-codes).
STATUS_NAMES = {
    0: "OK", 3: "INVALID_ARGUMENT", 5: "NOT_FOUND", 7: "PERMISSION_DENIED",
    12: "UNIMPLEMENTED", 13: "INTERNAL", 14: "UNAVAILABLE", 16: "UNAUTHENTICATED",
}


# --------------------------------------------------------------------------- #
# gRPC-Web framing (pure)
# --------------------------------------------------------------------------- #
def frame_message(payload: bytes, *, trailer: bool = False) -> bytes:
    """Wrap *payload* in a gRPC-Web frame: ``[flag][uint32 BE length][payload]`` (pure)."""

    flag = 0x80 if trailer else 0x00
    return bytes([flag]) + struct.pack(">I", len(payload)) + payload


def parse_frames(body: bytes) -> list[tuple[int, bytes]]:
    """Split a gRPC-Web body into ``[(flag, payload), …]``; stops at the first truncated
    frame rather than raising (pure)."""

    out: list[tuple[int, bytes]] = []
    i, n = 0, len(body)
    while i + 5 <= n:
        flag = body[i]
        (length,) = struct.unpack(">I", body[i + 1:i + 5])
        payload = body[i + 5:i + 5 + length]
        if len(payload) < length:
            break                                    # truncated final frame
        out.append((flag, payload))
        i += 5 + length
    return out


_B64_SEG = re.compile(rb"[A-Za-z0-9+/]+={0,2}")


def decode_body(body: bytes, content_type: str) -> bytes:
    """gRPC-Web-text responses base64-encode the frame stream; binary ones don't. Some servers
    flush each frame as its OWN padded base64 segment, so a single ``b64decode`` would stop at
    the first ``=`` and drop later frames (incl. the grpc-status trailer). Decode each padded
    segment independently and concatenate; a single whole-stream blob is just one segment (pure)."""

    if "grpc-web-text" not in (content_type or "").lower():
        return body
    out = bytearray()
    for seg in _B64_SEG.findall(body or b""):
        try:
            out += base64.b64decode(seg)
        except (ValueError, TypeError):
            continue
    return bytes(out)


def trailer_status(frames: list[tuple[int, bytes]], headers: dict[str, str]) -> tuple[int | None, str | None]:
    """Extract ``(grpc-status, grpc-message)`` — from the trailer frame (flag ``0x80``) if
    present, else from response headers (native gRPC puts them there) (pure)."""

    for flag, payload in frames:
        if flag & 0x80:
            kv: dict[str, str] = {}
            for line in payload.decode("latin-1", "replace").replace("\r\n", "\n").split("\n"):
                if ":" in line:
                    k, _, v = line.partition(":")
                    kv[k.strip().lower()] = v.strip()
            if "grpc-status" in kv:
                try:
                    return int(kv["grpc-status"]), kv.get("grpc-message")
                except ValueError:
                    return None, kv.get("grpc-message")
    hs = headers.get("grpc-status")
    if hs is not None:
        try:
            return int(hs), headers.get("grpc-message")
        except ValueError:
            return None, headers.get("grpc-message")
    return None, None


def data_payloads(frames: list[tuple[int, bytes]]) -> list[bytes]:
    """The non-trailer (data) frame payloads (pure)."""

    return [payload for flag, payload in frames if not (flag & 0x80)]


# --------------------------------------------------------------------------- #
# request builders (pure)
# --------------------------------------------------------------------------- #
def reflection_request() -> bytes:
    """A framed ``ServerReflectionRequest{ list_services: "*" }`` — field 7 (``list_services``,
    wire type 2), value ``"*"`` (pure)."""

    inner = b"\x3a\x01*"                              # tag=0x3a (field 7, len-delim), len=1, '*'
    return frame_message(inner)


def health_request() -> bytes:
    """A framed ``HealthCheckRequest{ service: "" }`` — empty message = overall health (pure)."""

    return frame_message(b"")


def probe_request() -> bytes:
    """A framed empty message for the invented fingerprint method (pure)."""

    return frame_message(b"")


# --------------------------------------------------------------------------- #
# minimal protobuf reader — extract leaked service names (pure)
# --------------------------------------------------------------------------- #
def _read_varint(b: bytes, i: int) -> tuple[int, int]:
    shift = val = 0
    while i < len(b):
        byte = b[i]
        i += 1
        val |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return val, i
        shift += 7
    return val, i


def _iter_fields(b: bytes):
    """Yield ``(field_number, wire_type, value)`` for a protobuf message; value is an int for
    varints and bytes for length-delimited fields. Stops on a malformed tail (pure)."""

    i, n = 0, len(b)
    while i < n:
        tag, i = _read_varint(b, i)
        field_no, wire = tag >> 3, tag & 7
        if wire == 0:
            val, i = _read_varint(b, i)
            yield field_no, wire, val
        elif wire == 2:
            ln, i = _read_varint(b, i)
            if i + ln > n:
                break
            yield field_no, wire, b[i:i + ln]
            i += ln
        elif wire == 5:
            yield field_no, wire, b[i:i + 4]
            i += 4
        elif wire == 1:
            yield field_no, wire, b[i:i + 8]
            i += 8
        else:
            break


def extract_service_names(payload: bytes) -> list[str]:
    """Pull service names out of a ``ServerReflectionResponse``: field 6 =
    ``list_services_response``; its field 1 (repeated) = ``ServiceResponse``; whose field 1 =
    ``name`` (string). Best-effort — returns [] if the shape doesn't match (pure)."""

    names: list[str] = []
    for fno, wire, val in _iter_fields(payload):
        if fno == 6 and wire == 2:                    # list_services_response
            for f2, w2, v2 in _iter_fields(val):
                if f2 == 1 and w2 == 2:               # service (ServiceResponse)
                    for f3, w3, v3 in _iter_fields(v2):
                        if f3 == 1 and w3 == 2:       # name
                            try:
                                names.append(v3.decode("utf-8"))
                            except UnicodeDecodeError:
                                pass
    # dedup, preserve order
    seen: dict[str, None] = {}
    for s in names:
        seen.setdefault(s, None)
    return list(seen)


# --------------------------------------------------------------------------- #
# response classification (pure)
# --------------------------------------------------------------------------- #
def is_grpc_response(content_type: str, grpc_status: int | None) -> bool:
    """A response is gRPC if its content-type is ``application/grpc*`` or it carries a
    ``grpc-status`` (a bogus method still answers UNIMPLEMENTED with the gRPC framing) (pure)."""

    ct = (content_type or "").lower()
    return ct.startswith("application/grpc") or grpc_status is not None


def status_name(code: int | None) -> str:
    return STATUS_NAMES.get(code, f"code {code}") if code is not None else "no grpc-status"


# --------------------------------------------------------------------------- #
# async probe
# --------------------------------------------------------------------------- #
async def probe_grpc(client, base_url: str, *, base_path: str = "", scope_check=None) -> dict:
    """Fingerprint gRPC/gRPC-Web at *base_url* and check reflection + health exposure. Sends
    three benign gRPC-Web unary calls (fingerprint, reflection ListServices, health Check);
    reads only metadata. ``base_path`` prefixes the RPC path for gateways mounted off root."""

    # Normalise base_path to a leading-slash path segment: a bare prefix like "grpc" would
    # otherwise concatenate onto the host ("https://hostgrpc") and target a DIFFERENT host —
    # an out-of-scope request. Empty means "mounted at root".
    bp = base_path.strip()
    if bp and not bp.startswith("/"):
        bp = "/" + bp
    root = base_url.rstrip("/") + bp.rstrip("/")

    async def _call(service: str, method: str, body: bytes) -> dict:
        url = f"{root}/{service}/{method}"
        r = await client.fetch(url, method="POST", body=body, headers=dict(REQUEST_HEADERS),
                               follow_redirects=False, timeout=12.0, scope_check=scope_check)
        # headers_map() preserves the server's wire case (Go/nginx emit Title-Case), so
        # lower-case the keys before any lookup — otherwise `Content-Type` / `Grpc-Status`
        # are missed and a real gRPC host is scored not_grpc.
        raw = r.headers_map() if hasattr(r, "headers_map") else {}
        hmap = {k.lower(): v for k, v in raw.items()}
        ct = hmap.get("content-type", "")
        frames = parse_frames(decode_body(r.body or b"", ct))
        code, msg = trailer_status(frames, hmap)
        return {"status": r.status, "content_type": ct, "grpc_status": code,
                "grpc_message": msg, "frames": frames}

    # 1) fingerprint via an invented method: a real gRPC server answers UNIMPLEMENTED (12) with
    #    the gRPC framing/content-type; anything else is (probably) not gRPC-Web at this path.
    fp = await _call(PROBE_SERVICE, PROBE_METHOD, probe_request())
    is_grpc = is_grpc_response(fp["content_type"], fp["grpc_status"])

    result: dict = {"target": root, "transport": "grpc-web", "is_grpc": is_grpc,
                    "findings": [], "services": []}
    if not is_grpc:
        result["verdict"] = "not_grpc"
        result["note"] = (f"no gRPC-Web response at {root} (fingerprint returned HTTP "
                          f"{fp['status']}, content-type {fp['content_type'] or 'none'}, no "
                          "grpc-status). Native gRPC needs HTTP/2; try a known base_path.")
        return result

    result["fingerprint"] = {"grpc_status": fp["grpc_status"],
                             "grpc_status_name": status_name(fp["grpc_status"])}

    # 2) reflection: ListServices against v1alpha then v1 (v1alpha is deprecated, so a server
    #    may implement only one — try both; only a grpc-status 0 confirms it, and stop there).
    for svc in (REFLECTION_V1ALPHA, REFLECTION_V1):
        refl = await _call(svc, REFLECTION_METHOD, reflection_request())
        if refl["grpc_status"] == 0:
            services: list[str] = []
            for payload in data_payloads(refl["frames"]):
                services += extract_service_names(payload)
            result["services"] = services
            result["findings"].append({
                "kind": "server_reflection", "service": svc, "severity": "medium",
                "detail": (f"gRPC Server Reflection is ENABLED ({svc}) — anyone can enumerate "
                           "every service/method/message without the .proto. Disable it in "
                           "production; map the surface with grpcurl, weaponize via Strix."
                           + (f" Leaked services: {', '.join(services)}." if services else ""))})
            break

    # 3) health service exposure.
    health = await _call(HEALTH_SERVICE, HEALTH_METHOD, health_request())
    if health["grpc_status"] == 0:
        result["findings"].append({
            "kind": "health_service", "service": HEALTH_SERVICE, "severity": "low",
            "detail": ("the standard grpc.health.v1.Health/Check service answers unauthenticated "
                       "— a liveness/enumeration information leak.")})

    reflection_on = any(f["kind"] == "server_reflection" for f in result["findings"])
    result["verdict"] = "reflection_exposed" if reflection_on else "grpc_detected"
    return result


def payloads() -> list[str]:
    """Human-readable dry-run preview of the benign RPCs the probe issues (pure)."""

    return [
        f"POST /{PROBE_SERVICE}/{PROBE_METHOD}  (empty gRPC-Web frame — fingerprint)",
        f"POST /{REFLECTION_V1ALPHA}/{REFLECTION_METHOD}  (ServerReflectionRequest list_services='*')",
        f"POST /{REFLECTION_V1}/{REFLECTION_METHOD}  (ServerReflectionRequest list_services='*')",
        f"POST /{HEALTH_SERVICE}/{HEALTH_METHOD}  (empty HealthCheckRequest)",
    ]
