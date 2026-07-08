"""WAF efficacy & bypass testing (authorised testing only).

Sends **benign canary** payloads (each contains the marker ``moonmcp`` and does
nothing harmful) across the common attack categories to learn what the WAF
actually blocks — then applies simple transforms (encoding, case, comments) to
see whether trivial obfuscation slips past it.  This is how you demonstrate that
a WAF is (or isn't) effective, without exploiting anything.

Intrusive: sends attack-shaped requests, so the server gates it behind
``MOONMCP_ALLOW_INTRUSIVE`` and the scope check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote

from ..net.http import HttpClient

_BLOCK_STATUSES = {403, 406, 429, 501, 999}
_BLOCK_SIGNS = ("access denied", "request blocked", "forbidden", "not acceptable",
                "web application firewall", "blocked by", "security policy",
                "incident id", "ray id", "mod_security", "406 not acceptable")

# category -> benign canary payload
_PAYLOADS = {
    "xss": "<script>moonmcp(1)</script>",
    "sqli": "1' OR moonmcp='moonmcp",
    "lfi": "../../../../moonmcp/etc/passwd",
    "rce": ";moonmcp;whoami",
    "ssti": "{{7*moonmcp}}",
    "traversal": "....//....//moonmcp",
    "xxe": "<!DOCTYPE moonmcp [<!ENTITY x SYSTEM 'file:///moonmcp'>]>",
}

# name -> transform function (applied to the raw payload before URL-encoding)
_TRANSFORMS = {
    "case-swap": lambda p: p.swapcase(),
    "comment-break": lambda p: p.replace(" ", "/**/").replace("script", "scr/**/ipt"),
    "double-encode": lambda p: quote(p),  # then the sender encodes once more
    "null-byte": lambda p: p + "%00",
    "mixed": lambda p: p.replace("<", "%3C").replace(">", "%3E"),
}


@dataclass
class CategoryResult:
    category: str
    baseline_status: int | None
    payload_status: int | None
    blocked: bool
    bypassed: bool = False
    bypass_transform: str | None = None
    bypass_status: int | None = None


@dataclass
class WafEfficacyResult:
    url: str
    protected_categories: list[str] = field(default_factory=list)
    unprotected_categories: list[str] = field(default_factory=list)
    bypasses: list[dict] = field(default_factory=list)
    details: list[CategoryResult] = field(default_factory=list)
    error: str | None = None


def _looks_blocked(status: int | None, body: str) -> bool:
    if status in _BLOCK_STATUSES:
        return True
    low = body.lower()
    return any(s in low for s in _BLOCK_SIGNS)


async def _send(client: HttpClient, url: str, value: str, scope_check) -> tuple[int | None, bool]:
    sep = "&" if "?" in url else "?"
    probe = f"{url}{sep}moonmcp={quote(value, safe='%')}"
    r = await client.fetch(probe, follow_redirects=False, timeout=10.0, scope_check=scope_check)
    if r.status is None:
        return None, False
    return r.status, _looks_blocked(r.status, r.text(limit=20_000))


async def test_waf_efficacy(client: HttpClient, url: str, *, scope_check=None) -> WafEfficacyResult:
    result = WafEfficacyResult(url=url)
    baseline = await client.fetch(url, follow_redirects=False, timeout=10.0, scope_check=scope_check)
    if baseline.status is None:
        result.error = baseline.error or "unreachable"
        return result

    for category, payload in _PAYLOADS.items():
        status, blocked = await _send(client, url, payload, scope_check)
        detail = CategoryResult(category=category, baseline_status=baseline.status,
                                payload_status=status, blocked=blocked)
        if blocked:
            result.protected_categories.append(category)
            # Try to slip past with simple transforms.
            for tname, tfunc in _TRANSFORMS.items():
                try:
                    transformed = tfunc(payload)
                except Exception:
                    continue
                t_status, t_blocked = await _send(client, url, transformed, scope_check)
                if not t_blocked and t_status is not None:
                    detail.bypassed = True
                    detail.bypass_transform = tname
                    detail.bypass_status = t_status
                    result.bypasses.append({"category": category, "transform": tname,
                                            "status": t_status})
                    break
        else:
            result.unprotected_categories.append(category)
        result.details.append(detail)
    return result
