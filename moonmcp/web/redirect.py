"""Open-redirect detection.

Injects an external canary host into the common redirect parameters and checks
whether the server bounces to it (via a ``Location`` header or a meta-refresh /
JS redirect in the body).  Requests are sent with redirects disabled, so the
canary is never actually contacted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit, urlunsplit

from ..net.http import HttpClient

REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_uri", "redirect_url", "redirectUrl",
    "return", "returnTo", "return_url", "returnUrl", "dest", "destination",
    "continue", "goto", "go", "r", "u", "link", "target", "out", "view",
    "to", "image_url", "callback", "checkout_url", "rurl", "forward",
]

_CANARY = "moonmcp-open-redirect.example"
_PAYLOADS = [f"https://{_CANARY}/", f"//{_CANARY}/", f"https:/{_CANARY}"]

_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+url=([^"'>\s]+)""", re.IGNORECASE)
_JS_REDIRECT_RE = re.compile(
    r"""(?:location\.(?:href|replace)\s*[=(]|window\.location\s*=)\s*['"]([^'"]+)['"]""", re.IGNORECASE)


@dataclass
class RedirectFinding:
    parameter: str
    payload: str
    via: str          # "Location header" | "meta refresh" | "js redirect"
    evidence: str


@dataclass
class OpenRedirectResult:
    url: str
    vulnerable: bool = False
    findings: list[RedirectFinding] = field(default_factory=list)
    tested_params: int = 0
    error: str | None = None


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = parts.query
    extra = urlencode({param: value})
    new_query = f"{query}&{extra}" if query else extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", new_query, parts.fragment))


def _points_to_canary(value: str) -> bool:
    v = value.strip().lower()
    return _CANARY in v and (v.startswith(("http://", "https://", "//")) or v.startswith(("https:/", "http:/")))


async def check_open_redirect(
    client: HttpClient, url: str, *, scope_check=None, params: list[str] | None = None
) -> OpenRedirectResult:
    result = OpenRedirectResult(url=url)
    baseline = await client.fetch(url, follow_redirects=False, timeout=10.0, scope_check=scope_check)
    if baseline.status is None:
        result.error = baseline.error or "unreachable"
        return result

    to_test = params or REDIRECT_PARAMS
    result.tested_params = len(to_test)
    for param in to_test:
        for payload in _PAYLOADS:
            test_url = _with_param(url, param, payload)
            r = await client.fetch(test_url, follow_redirects=False, timeout=10.0, scope_check=scope_check)
            if r.status is None:
                continue
            # 1) Location-header redirect to the canary.
            if r.status and 300 <= r.status < 400:
                loc = r.header("Location") or ""
                if _points_to_canary(loc):
                    result.vulnerable = True
                    result.findings.append(RedirectFinding(param, payload, "Location header", loc[:200]))
                    break
            # 2) meta-refresh or JS redirect in the body.
            if r.body:
                body = r.text(limit=50_000)
                for rx, via in ((_META_REFRESH_RE, "meta refresh"), (_JS_REDIRECT_RE, "js redirect")):
                    m = rx.search(body)
                    if m and _points_to_canary(m.group(1)):
                        result.vulnerable = True
                        result.findings.append(RedirectFinding(param, payload, via, m.group(1)[:200]))
                        break
            if result.findings and result.findings[-1].parameter == param:
                break
    return result
