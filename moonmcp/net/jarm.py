"""JARM — active TLS server fingerprinting.

A faithful re-implementation of the JARM algorithm (10 crafted TLS Client Hellos
whose Server Hello responses are folded into a 62-character fuzzy hash).  Two
servers with the same JARM are configured the same way at the TLS layer, which is
a strong pivot for finding sibling infrastructure / origin servers and for
spotting known stacks (and C2) via public JARM databases.

The algorithm and the exact probe/cipher definitions are from Salesforce's JARM:

    Copyright (c) 2020, salesforce.com, inc. All rights reserved.
    Licensed under the BSD 3-Clause license.
    https://github.com/salesforce/jarm

This module is an independent async port of that BSD-3-Clause algorithm.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import struct
from dataclasses import dataclass

_GREASE = [b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a", b"\x4a\x4a", b"\x5a\x5a",
           b"\x6a\x6a", b"\x7a\x7a", b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba",
           b"\xca\xca", b"\xda\xda", b"\xea\xea", b"\xfa\xfa"]

_CIPHERS_ALL = [
    b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e", b"\x00\x39",
    b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88",
    b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac", b"\xc0\xae",
    b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72",
    b"\xc0\x73", b"\xcc\xa9", b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12",
    b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60",
    b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\x13\x05", b"\x13\x04", b"\x13\x03",
    b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c", b"\xc0\xa0",
    b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d", b"\xc0\xa1", b"\x00\x9d", b"\x00\x41",
    b"\x00\xba", b"\x00\x84", b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05",
]
_CIPHERS_NO13 = [c for c in _CIPHERS_ALL if not c.startswith(b"\x13")]

# For the fuzzy hash: the canonical cipher index table.
_CIPHER_INDEX = [
    b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16", b"\x00\x2f", b"\x00\x33",
    b"\x00\x35", b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41", b"\x00\x45", b"\x00\x67",
    b"\x00\x6b", b"\x00\x84", b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d", b"\x00\x9e",
    b"\x00\x9f", b"\x00\xba", b"\x00\xbe", b"\x00\xc0", b"\x00\xc4", b"\xc0\x07", b"\xc0\x08",
    b"\xc0\x09", b"\xc0\x0a", b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23",
    b"\xc0\x24", b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c", b"\xc0\x2f", b"\xc0\x30",
    b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73", b"\xc0\x76", b"\xc0\x77", b"\xc0\x9c",
    b"\xc0\x9d", b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1", b"\xc0\xa2", b"\xc0\xa3",
    b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf", b"\xcc\x13", b"\xcc\x14", b"\xcc\xa8",
    b"\xcc\xa9", b"\x13\x01", b"\x13\x02", b"\x13\x03", b"\x13\x04", b"\x13\x05",
]

_VERSION_OPTIONS = "abcdef"


def _choose_grease() -> bytes:
    # Vary by process randomness; GREASE only feeds the extension hash.
    return _GREASE[os.urandom(1)[0] % len(_GREASE)]


def _mung(items: list[bytes], order: str) -> list[bytes]:
    n = len(items)
    if order == "REVERSE":
        return items[::-1]
    if order == "BOTTOM_HALF":
        return items[n // 2 + 1:] if n % 2 == 1 else items[n // 2:]
    if order == "TOP_HALF":
        out: list[bytes] = []
        if n % 2 == 1:
            out.append(items[n // 2])
        out += _mung(_mung(items, "REVERSE"), "BOTTOM_HALF")
        return out
    if order == "MIDDLE_OUT":
        mid = n // 2
        out = []
        if n % 2 == 1:
            out.append(items[mid])
            for i in range(1, mid + 1):
                out.append(items[mid + i])
                out.append(items[mid - i])
        else:
            for i in range(1, mid + 1):
                out.append(items[mid - 1 + i])
                out.append(items[mid - i])
        return out
    return items


def _get_ciphers(d: list) -> bytes:
    items = list(_CIPHERS_ALL if d[3] == "ALL" else _CIPHERS_NO13)
    if d[4] != "FORWARD":
        items = _mung(items, d[4])
    if d[5] == "GREASE":
        items.insert(0, _choose_grease())
    return b"".join(items)


def _ext_sni(host: str) -> bytes:
    h = host.encode()
    return (b"\x00\x00" + struct.pack(">H", len(h) + 5) + struct.pack(">H", len(h) + 3)
            + b"\x00" + struct.pack(">H", len(h)) + h)


def _ext_alpn(d: list) -> bytes:
    if d[6] == "RARE_APLN":
        alpns = [b"\x08http/0.9", b"\x08http/1.0", b"\x06spdy/1", b"\x06spdy/2",
                 b"\x06spdy/3", b"\x03h2c", b"\x02hq"]
    else:
        alpns = [b"\x08http/0.9", b"\x08http/1.0", b"\x08http/1.1", b"\x06spdy/1",
                 b"\x06spdy/2", b"\x06spdy/3", b"\x02h2", b"\x03h2c", b"\x02hq"]
    if d[8] != "FORWARD":
        alpns = _mung(alpns, d[8])
    body = b"".join(alpns)
    return b"\x00\x10" + struct.pack(">H", len(body) + 2) + struct.pack(">H", len(body)) + body


def _ext_key_share(grease: bool) -> bytes:
    share = (_choose_grease() + b"\x00\x01\x00") if grease else b""
    share += b"\x00\x1d" + b"\x00\x20" + os.urandom(32)
    return b"\x00\x33" + struct.pack(">H", len(share) + 2) + struct.pack(">H", len(share)) + share


def _ext_supported_versions(d: list, grease: bool) -> bytes:
    tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03"] if d[7] == "1.2_SUPPORT" \
        else [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
    if d[8] != "FORWARD":
        tls = _mung(tls, d[8])
    versions = (_choose_grease() if grease else b"") + b"".join(tls)
    return b"\x00\x2b" + struct.pack(">H", len(versions) + 1) + struct.pack(">B", len(versions)) + versions


def _get_extensions(d: list) -> bytes:
    grease = d[5] == "GREASE"
    ext = b""
    if grease:
        ext += _choose_grease() + b"\x00\x00"
    ext += _ext_sni(d[0])
    ext += b"\x00\x17\x00\x00"                              # extended_master_secret
    ext += b"\x00\x01\x00\x01\x01"                          # max_fragment_length
    ext += b"\xff\x01\x00\x01\x00"                          # renegotiation_info
    ext += b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"  # supported_groups
    ext += b"\x00\x0b\x00\x02\x01\x00"                      # ec_point_formats
    ext += b"\x00\x23\x00\x00"                              # session_ticket
    ext += _ext_alpn(d)
    ext += (b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03"
            b"\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01")     # signature_algorithms
    ext += _ext_key_share(grease)
    ext += b"\x00\x2d\x00\x02\x01\x01"                      # psk_key_exchange_modes
    if d[2] == "TLS_1.3" or d[7] == "1.2_SUPPORT":
        ext += _ext_supported_versions(d, grease)
    return struct.pack(">H", len(ext)) + ext


def build_client_hello(d: list) -> bytes:
    version = {"TLS_1.3": b"\x03\x01", "SSLv3": b"\x03\x00", "TLS_1": b"\x03\x01",
               "TLS_1.1": b"\x03\x02", "TLS_1.2": b"\x03\x03"}
    record_ver = version[d[2]]
    ch_ver = b"\x03\x03" if d[2] == "TLS_1.3" else record_ver
    ch = ch_ver + os.urandom(32)
    sid = os.urandom(32)
    ch += struct.pack(">B", len(sid)) + sid
    ciphers = _get_ciphers(d)
    ch += struct.pack(">H", len(ciphers)) + ciphers
    ch += b"\x01\x00"  # compression methods
    ch += _get_extensions(d)
    hs = b"\x01" + b"\x00" + struct.pack(">H", len(ch)) + ch
    return b"\x16" + record_ver + struct.pack(">H", len(hs)) + hs


def _read_server_hello(data: bytes) -> str:
    try:
        if not data:
            return "|||"
        if data[0] == 21:
            return "|||"
        if data[0] == 22 and data[5] == 2:
            server_hello_length = int.from_bytes(data[3:5], "big")
            counter = data[43]
            selected_cipher = data[counter + 44:counter + 46]
            version = data[9:11]
            out = selected_cipher.hex() + "|" + version.hex() + "|"
            out += _extract_ext_info(data, counter, server_hello_length)
            return out
        return "|||"
    except (IndexError, ValueError):
        return "|||"


def _extract_ext_info(data: bytes, counter: int, server_hello_length: int) -> str:
    try:
        if data[counter + 47] == 11:
            return "|"
        if data[counter + 50:counter + 53] == b"\x0e\xac\x0b" or data[82:85] == b"\x0f\xf0\x0b":
            return "|"
        if counter + 42 >= server_hello_length:
            return "|"
        count = 49 + counter
        length = int.from_bytes(data[counter + 47:counter + 49], "big")
        maximum = length + (count - 1)
        types: list[bytes] = []
        values: list[bytes | str] = []
        while count < maximum:
            types.append(data[count:count + 2])
            ext_length = int.from_bytes(data[count + 2:count + 4], "big")
            if ext_length == 0:
                count += 4
                values.append("")
            else:
                values.append(data[count + 4:count + 4 + ext_length])
                count += ext_length + 4
        alpn = _find_ext(b"\x00\x10", types, values)
        result = str(alpn) + "|"
        result += "-".join(t.hex() for t in types)
        return result
    except (IndexError, ValueError):
        return "|"


def _find_ext(ext_type: bytes, types: list, values: list) -> str:
    for i, t in enumerate(types):
        if t == ext_type:
            v = values[i]
            if ext_type == b"\x00\x10" and isinstance(v, (bytes, bytearray)):
                return v[3:].decode(errors="replace")
            return v.hex() if isinstance(v, (bytes, bytearray)) else ""
    return ""


def _cipher_byte(cipher_hex: str) -> str:
    if cipher_hex == "":
        return "00"
    count = 1
    for b in _CIPHER_INDEX:
        if cipher_hex == b.hex():
            break
        count += 1
    h = format(count, "x")
    return h if len(h) >= 2 else "0" + h


def _version_byte(version_hex: str) -> str:
    if version_hex == "":
        return "0"
    try:
        count = int(version_hex[3:4])
    except (ValueError, IndexError):
        return "0"
    return _VERSION_OPTIONS[count] if 0 <= count < len(_VERSION_OPTIONS) else "0"


def jarm_hash(jarm_raw: str) -> str:
    if jarm_raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||":
        return "0" * 62
    fuzzy = ""
    alpns_and_ext = ""
    for handshake in jarm_raw.split(","):
        parts = handshake.split("|")
        fuzzy += _cipher_byte(parts[0])
        fuzzy += _version_byte(parts[1])
        alpns_and_ext += parts[2] + parts[3]
    fuzzy += hashlib.sha256(alpns_and_ext.encode()).hexdigest()[0:32]
    return fuzzy


def _queue(host: str, port: int) -> list[list]:
    return [
        [host, port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"],
        [host, port, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"],
        [host, port, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
        [host, port, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
    ]


@dataclass
class JarmResult:
    host: str
    port: int
    fingerprint: str = "0" * 62
    is_null: bool = True
    error: str | None = None


async def _probe(host: str, port: int, details: list, timeout: float) -> str:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return "|||"
    try:
        writer.write(build_client_hello(details))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1484), timeout=timeout)
        return _read_server_hello(bytes(data))
    except (asyncio.TimeoutError, OSError):
        return "|||"
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except (asyncio.TimeoutError, OSError):
            pass


async def compute_jarm(host: str, port: int = 443, timeout: float = 15.0) -> JarmResult:
    results = []
    for details in _queue(host, port):
        results.append(await _probe(host, port, details, timeout))
    raw = ",".join(results)
    fp = jarm_hash(raw)
    return JarmResult(host=host, port=port, fingerprint=fp, is_null=(fp == "0" * 62))
