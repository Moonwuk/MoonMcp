"""Passive deserialization-format fingerprinting (Freddy-lite).

Scans an already-captured value (a cookie/header/hidden-field/body blob you
already have) for the byte-level or base64 **signatures** of common
object-serialization formats: Java native serialization, .NET ViewState
(LosFormatter), PHP ``serialize()`` objects, Python pickle, Ruby ``Marshal``, and
Fastjson/Jackson polymorphic-type JSON markers.

100% passive pattern matching over data other tools already fetched — no new
network traffic, no forged gadget chain, no ysoserial/PHPGGC/ViewGen invocation.
Output is a lead ("this looks like a raw Java-serialized blob") for the caller to
hand to the appropriate exploitation tool via Strix, matching the same
"classify, don't exploit" boundary as `extract_secrets`/`db_credential_scan`.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

_JAVA_MAGIC = b"\xac\xed\x00\x05"
_NET_VIEWSTATE_MAGIC = b"\xff\x01"
_RUBY_MARSHAL_MAGIC = b"\x04\x08"
_PICKLE_PROTOS: dict[int, bytes] = {2: b"\x80\x02", 3: b"\x80\x03", 4: b"\x80\x04", 5: b"\x80\x05"}

_PHP_OBJECT_RE = re.compile(r'O:\d+:"[A-Za-z_][\w\\]*":\d+:\{')
_FASTJSON_TYPE_RE = re.compile(r'"@(?:type|class)"\s*:\s*"')
_B64ISH_RE = re.compile(r"[A-Za-z0-9+/=_-]{4,}")


@dataclass
class SerializationHit:
    format: str
    framework: str
    severity: str
    detail: str
    encoding: str   # "raw" or "base64"


def _try_b64(text: str) -> bytes | None:
    t = text.strip()
    if not _B64ISH_RE.fullmatch(t):
        return None
    normalized = t.replace("-", "+").replace("_", "/")
    pad = "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized + pad)
    except Exception:  # noqa: BLE001 - a non-b64 blob must never crash the scanner
        return None


def _check_binary(data: bytes, encoding: str, hits: list[SerializationHit]) -> None:
    if data.startswith(_JAVA_MAGIC):
        hits.append(SerializationHit(
            "java-serialization", "Java native serialization", "critical",
            "Starts with the Java serialization magic bytes (ACED0005) — a classic "
            "gadget-chain deserialization sink (ysoserial).", encoding))
    if data.startswith(_NET_VIEWSTATE_MAGIC):
        hits.append(SerializationHit(
            ".net-viewstate", ".NET ViewState (LosFormatter)", "high",
            "Starts with the LosFormatter FF01 header — unencrypted ASP.NET ViewState "
            "(check EnableViewStateMac; ViewGen/ysoserial.net if MAC is off or the "
            "machineKey is known).", encoding))
    for proto, magic in _PICKLE_PROTOS.items():
        if data.startswith(magic):
            hits.append(SerializationHit(
                "python-pickle", f"Python pickle (protocol {proto})", "critical",
                "Starts with a Python pickle protocol marker — arbitrary-code-execution "
                "sink on unpickle.", encoding))
    if data.startswith(_RUBY_MARSHAL_MAGIC):
        hits.append(SerializationHit(
            "ruby-marshal", "Ruby Marshal", "critical",
            "Starts with the Ruby Marshal 4.8 header — a gadget-chain deserialization "
            "sink.", encoding))


def detect_markers(blob: str) -> list[SerializationHit]:
    """Scan *blob* (text, possibly base64-encoded) for serialization-format
    signatures (pure). A base64-looking blob is decoded and checked alongside the
    raw text so both a raw binary paste and a base64-transported cookie/param value
    are covered."""

    hits: list[SerializationHit] = []
    raw_bytes = blob.encode("latin-1", errors="ignore")
    _check_binary(raw_bytes, "raw", hits)
    decoded = _try_b64(blob)
    if decoded is not None and decoded != raw_bytes:
        _check_binary(decoded, "base64", hits)
    if _PHP_OBJECT_RE.search(blob):
        hits.append(SerializationHit(
            "php-object", "PHP serialize() object", "high",
            'Matches PHP\'s O:<len>:"ClassName": object-serialization format — a PHP '
            "Object Injection sink if reachable (magic __wakeup/__destruct methods).",
            "raw"))
    if _FASTJSON_TYPE_RE.search(blob):
        hits.append(SerializationHit(
            "json-polymorphic", "Fastjson/Jackson polymorphic type", "high",
            "JSON body carries an @type/@class field — a polymorphic-deserialization "
            "sink (Fastjson autoType, Jackson @JsonTypeInfo) if the framework "
            "instantiates it.", "raw"))
    return hits
