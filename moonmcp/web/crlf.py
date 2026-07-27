"""CRLF injection / HTTP response splitting detection.

A parameter reflected into a response header (a redirect ``Location``, a
``Set-Cookie``, a routing/lang value) that doesn't strip CR/LF lets an attacker
inject their own header line — response splitting, header injection, cookie
injection, and open-redirect-via-``Location``. Real bounties: X/xAI, Twitter
``?lang=``, Uber subdomain routing, PayPal.

Safe detection = inject a BENIGN marker header via the parameter and check whether
it surfaces as a *real* response header (not just reflected in the body). We never
inject a dangerous header — only a neutral marker header / a benign marker cookie.
The marker carries no tool name so the probe doesn't fingerprint MoonMCP.
"""

from __future__ import annotations

from collections.abc import Callable

from ..net.http import HttpClient
from .inject import inject_raw

_MARKER_HEADER = "x-crlf-probe-inj"
_MARKER_VALUE = "1"
_MARKER_COOKIE = "crlfprobe"

# Each payload URL-encodes a CR/LF that, if not stripped, starts a new header line.
# Variants cover bare-LF, space-folding, fragment prefix, overlong/unicode CR-LF,
# double-URL-encoding (decoded by some proxies), and a Set-Cookie split.
CRLF_PAYLOADS = [
    "canary%0d%0aX-Crlf-Probe-Inj:1",
    "canary%0aX-Crlf-Probe-Inj:1",
    "canary%0d%0a X-Crlf-Probe-Inj:1",
    "canary%23%0d%0aX-Crlf-Probe-Inj:1",
    "canary%E5%98%8A%E5%98%8DX-Crlf-Probe-Inj:1",
    "canary%250d%250aX-Crlf-Probe-Inj:1",
    "canary%0d%0aSet-Cookie:crlfprobe=1",
]


def assess(headers: dict[str, str], set_cookies: list[str]) -> bool:
    """Did an injected marker surface as a real response header / cookie?"""

    low = {k.lower(): (v or "") for k, v in headers.items()}
    if low.get(_MARKER_HEADER, "").strip() == _MARKER_VALUE:
        return True
    return any(_MARKER_COOKIE in (c or "").lower() for c in set_cookies)


async def probe_crlf(client: HttpClient, url: str, param: str, *, method: str = "GET",
                     scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Inject each CRLF payload into *param* and flag when the marker header/cookie
    surfaces in the response (proof of header injection / response splitting)."""

    findings: list[dict] = []
    for payload in CRLF_PAYLOADS:
        target = inject_raw(url, param, payload)
        r = await client.fetch(target, method=method.upper(), follow_redirects=False,
                               timeout=12.0, scope_check=scope_check)
        if r.status is None:
            continue
        if assess(r.headers_map(), r.get_all("set-cookie")):
            findings.append({
                "param": param, "payload": payload, "severity": "medium", "verdict": "confirmed",
                "detail": "the injected CR/LF surfaced as a real response header/cookie — HTTP "
                          "response splitting / header injection",
            })
            break  # one confirmed payload is enough
    return findings
