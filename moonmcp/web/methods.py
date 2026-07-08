"""HTTP method enumeration and risky-method detection.

Reads the ``Allow`` header from an ``OPTIONS`` request and actively probes a few
sensitive methods (TRACE, PUT, DELETE, PATCH) to see how the server responds —
an enabled TRACE (XST) or an accepted PUT/DELETE is worth a closer look.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..net.http import HttpClient

_RISKY = ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")


@dataclass
class MethodResult:
    url: str
    allow_header: list[str] = field(default_factory=list)
    tested: dict[str, int] = field(default_factory=dict)
    risky_enabled: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None


async def check_methods(client: HttpClient, url: str, *, scope_check=None) -> MethodResult:
    result = MethodResult(url=url)
    opt = await client.fetch(url, method="OPTIONS", follow_redirects=False, timeout=12.0,
                             scope_check=scope_check)
    if opt.status is None:
        result.error = opt.error or "unreachable"
        return result
    allow = opt.header("Allow") or opt.header("Access-Control-Allow-Methods") or ""
    result.allow_header = [m.strip().upper() for m in allow.split(",") if m.strip()]

    for method in _RISKY:
        r = await client.fetch(url, method=method, follow_redirects=False, timeout=10.0,
                               scope_check=scope_check)
        if r.status is None:
            continue
        result.tested[method] = r.status
        # 405/501 => rejected; 2xx (and for TRACE, a reflected body) => enabled.
        if method == "TRACE" and r.status == 200 and "TRACE" in r.text(limit=500).upper():
            result.risky_enabled.append("TRACE")
            result.notes.append("TRACE enabled — possible Cross-Site Tracing (XST)")
        elif r.status not in (0, 400, 401, 403, 404, 405, 501) and 200 <= r.status < 300:
            result.risky_enabled.append(method)
            result.notes.append(f"{method} returned {r.status} — verify it is not write-enabled")
    return result
