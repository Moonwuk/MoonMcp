"""HTTP method enumeration and risky-method detection.

Reads the ``Allow`` header from an ``OPTIONS`` request and actively probes a few
sensitive methods (TRACE, PUT, DELETE, PATCH) to see how the server responds —
an enabled TRACE (XST) or an accepted PUT/DELETE is worth a closer look.

**Safe-path probing:** PUT/DELETE/PATCH/CONNECT are sent to a throwaway
``/{random}.nonexistent`` path under the URL, NOT to the real URL. A 2xx on a
nonexistent path reveals the method is enabled without risking destruction of
the real resource (a DELETE on the real URL would delete it; a PUT would
create/overwrite). TRACE is bodyless and safe to send to the real URL.
(Audit 2026-07-27, WP1.)
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from ..net.http import HttpClient

# Methods that mutate state — probed against a throwaway path only.
_MUTATING = ("PUT", "DELETE", "PATCH", "CONNECT")
# TRACE is bodyless/reflection-only — safe to send to the real URL.
_RISKY = ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")


@dataclass
class MethodResult:
    url: str
    allow_header: list[str] = field(default_factory=list)
    tested: dict[str, int] = field(default_factory=dict)
    risky_enabled: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None


def _throwaway_path(url: str) -> str:
    """Return ``url`` with a random nonexistent path appended — for safe
    mutating-method probing. Keeps the query string empty so the probe can't
    be confused with a real resource."""
    sp = urlsplit(url)
    rand = secrets.token_hex(8)
    return urlunsplit((sp.scheme, sp.netloc, f"/{rand}.nonexistent", "", ""))


async def check_methods(client: HttpClient, url: str, *, scope_check=None) -> MethodResult:
    result = MethodResult(url=url)
    opt = await client.fetch(url, method="OPTIONS", follow_redirects=False, timeout=12.0,
                             scope_check=scope_check)
    if opt.status is None:
        result.error = opt.error or "unreachable"
        return result
    allow = opt.header("Allow") or opt.header("Access-Control-Allow-Methods") or ""
    result.allow_header = [m.strip().upper() for m in allow.split(",") if m.strip()]

    # Build a safe throwaway target for mutating methods.
    safe_url = _throwaway_path(url)
    for method in _RISKY:
        # Mutating methods → throwaway path; TRACE → real URL (bodyless, reflection-only).
        target = safe_url if method in _MUTATING else url
        r = await client.fetch(target, method=method, follow_redirects=False, timeout=10.0,
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
            result.notes.append(
                f"{method} returned {r.status} on a throwaway path — method is enabled; "
                "verify it is not write-enabled on real resources"
            )
    return result
