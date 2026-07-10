"""CORS misconfiguration detection.

Sends a handful of crafted ``Origin`` headers and inspects the
``Access-Control-Allow-Origin`` / ``-Allow-Credentials`` response headers for the
classic dangerous patterns: origin reflection, ``null`` acceptance, and
prefix/suffix bypasses — especially when credentials are also allowed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..net.http import HttpClient


@dataclass
class CorsFinding:
    test: str
    origin_sent: str
    acao: str | None
    acac: bool
    severity: str
    detail: str


@dataclass
class CorsResult:
    url: str
    findings: list[CorsFinding] = field(default_factory=list)
    reflects_arbitrary_origin: bool = False
    allows_credentials: bool = False
    error: str | None = None


def _probe_origins(host: str) -> dict[str, str]:
    root = host
    return {
        "arbitrary-origin": "https://moonmcp-cors-test.example",
        "null-origin": "null",
        "prefix-bypass": f"https://{root}.moonmcp-cors-test.example",
        "suffix-bypass": f"https://moonmcp{root}",
        "subdomain-trust": f"https://moonmcp-evil.{root}",
        "scheme-downgrade": f"http://{root}",
    }


async def audit_cors(client: HttpClient, url: str, *,
                     scope_check: Callable[[str], bool] | None = None) -> CorsResult:
    host = urlsplit(url).hostname or url
    result = CorsResult(url=url)
    # The baseline follows redirects — keep them in scope so engagement auth
    # headers can't be leaked to a third party via an open redirect.
    baseline = await client.fetch(url, follow_redirects=True, timeout=12.0,
                                  scope_check=scope_check)
    if baseline.status is None:
        result.error = baseline.error or "unreachable"
        return result

    for test, origin in _probe_origins(host).items():
        r = await client.fetch(
            url, method="GET", headers={"Origin": origin}, follow_redirects=False, timeout=12.0
        )
        if r.status is None:
            continue
        acao = r.header("Access-Control-Allow-Origin")
        acac = (r.header("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
        if not acao:
            continue

        reflected = acao == origin or (origin != "null" and acao.rstrip("/") == origin.rstrip("/"))
        severity, detail = None, ""
        if acao == "*" and acac:
            severity, detail = "high", "Wildcard ACAO with credentials (browsers block, but misconfigured)"
        elif origin == "null" and acao == "null":
            severity = "high" if acac else "medium"
            detail = "Server trusts the 'null' origin (reachable via sandboxed iframes)"
        elif reflected:
            severity = "high" if acac else "medium"
            detail = f"Origin reflected in ACAO{' with credentials' if acac else ''}"
            if test != "arbitrary-origin":
                result.reflects_arbitrary_origin = True
                detail = f"Origin bypass ({test}) reflected{' with credentials' if acac else ''}"
        elif acao == "*":
            severity, detail = "info", "Wildcard ACAO (no credentials; low risk unless sensitive data)"

        if origin != "null" and reflected and test == "arbitrary-origin":
            result.reflects_arbitrary_origin = True
        if acac:
            result.allows_credentials = True

        if severity:
            result.findings.append(
                CorsFinding(test=test, origin_sent=origin, acao=acao, acac=acac,
                            severity=severity, detail=detail)
            )
    return result
