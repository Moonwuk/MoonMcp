"""Behavioural profiling of a web target.

Rather than looking at *what* a server exposes, this looks at *how it behaves*:
how it handles a missing page, whether it leaks stack traces on error, whether it
reflects the Host / X-Forwarded-Host header (cache-poisoning / routing hints),
which methods it advertises, and how fast it responds.  All light, benign
requests — no bursts, no payloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..net.http import HttpClient

# Distinctive framework/language error+stack-trace markers. The ultra-generic phrases
# " on line ", "Warning: " and "stack trace" were removed: they appear in ordinary page
# copy (form helpers, cookie banners, docs), and a real error already trips a specific
# marker below ("Fatal error", "Traceback", ".java:", "SQLSTATE", ...).
_ERROR_SIGNATURES = [
    "Traceback (most recent call last)", "Whitelabel Error Page", "NullPointerException",
    "System.Web", "at java.", "ORA-", "SQLSTATE", "Fatal error",
    "Microsoft OLE DB", "You have an error in your SQL syntax",
    "/var/www/", "DEBUG = True", "Werkzeug Debugger", "django.", "Rails.root",
    "Exception Details", ".java:", "Undefined index",
]
_CANARY_HOST = "moonmcp-behaviour-canary.example"


@dataclass
class BehaviorProfile:
    url: str
    response_time_ms: float | None = None
    server: str | None = None
    not_found_status: int | None = None
    custom_404: bool = False
    soft_404: bool = False
    error_disclosure: list[str] = field(default_factory=list)
    host_header_reflected: bool = False
    xforwarded_host_reflected: bool = False
    allowed_methods: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None


async def profile_behavior(client: HttpClient, url: str, *, scope_check=None) -> BehaviorProfile:
    result = BehaviorProfile(url=url)
    base = await client.fetch(url, follow_redirects=True, timeout=12.0, scope_check=scope_check)
    if base.status is None:
        result.error = base.error or "unreachable"
        return result
    result.response_time_ms = base.elapsed_ms
    result.server = base.header("Server")
    base_body = base.text(limit=50_000)

    # 404 handling
    nf = await client.fetch(url.rstrip("/") + "/moonmcp-does-not-exist-9f2c",
                            follow_redirects=False, timeout=10.0, scope_check=scope_check)
    if nf.status is not None:
        result.not_found_status = nf.status
        if nf.status == 200:
            result.soft_404 = True
            result.notes.append("soft-404: nonexistent path returns 200 (breaks negative testing)")
        nf_body = nf.text(limit=50_000)
        if nf.status == 404 and nf_body and nf_body[:2000] != base_body[:2000] and len(nf_body) > 200:
            result.custom_404 = True

    # Error disclosure (trigger with odd input)
    for path in ("/%c0%ae%c0%ae/", "/?moonmcp[]=1", "/'\"><"):
        er = await client.fetch(url.rstrip("/") + path, follow_redirects=False,
                                timeout=10.0, scope_check=scope_check)
        if er.status is None or not er.body:
            continue
        body = er.text(limit=50_000)
        for sig in _ERROR_SIGNATURES:
            # a marker already present in the NORMAL page isn't error disclosure — it's
            # ordinary page copy that happens to contain the phrase.
            if sig in body and sig not in base_body and sig not in result.error_disclosure:
                result.error_disclosure.append(sig)
    if result.error_disclosure:
        result.notes.append("error/stack-trace signatures leaked in responses")

    # Host / X-Forwarded-Host reflection
    hh = await client.fetch(url, headers={"Host": _CANARY_HOST}, follow_redirects=False,
                            timeout=10.0, scope_check=scope_check)
    if hh.status is not None:
        loc = (hh.header("Location") or "")
        if _CANARY_HOST in loc or _CANARY_HOST in hh.text(limit=20_000):
            result.host_header_reflected = True
            result.notes.append("Host header reflected — check for host-header injection / cache poisoning")

    xf = await client.fetch(url, headers={"X-Forwarded-Host": _CANARY_HOST}, follow_redirects=False,
                            timeout=10.0, scope_check=scope_check)
    if xf.status is not None:
        loc = (xf.header("Location") or "")
        if _CANARY_HOST in loc or _CANARY_HOST in xf.text(limit=20_000):
            result.xforwarded_host_reflected = True
            result.notes.append("X-Forwarded-Host reflected — cache-poisoning / open-redirect candidate")

    # Allowed methods
    opt = await client.fetch(url, method="OPTIONS", follow_redirects=False, timeout=10.0, scope_check=scope_check)
    allow = (opt.header("Allow") or "") if opt.status is not None else ""
    result.allowed_methods = [m.strip().upper() for m in re.split(r"[,\s]+", allow) if m.strip()]
    return result
