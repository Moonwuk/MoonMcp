"""HTTP security-header analysis.

Given a response, grade the presence and quality of the well-known security
headers and flag risky cookies and information-leaking headers.  This is the
bread-and-butter of a bug-bounty "low-hanging fruit" pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..net.http import HttpResult

# header -> (severity, human explanation of why it matters when missing)
_SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "strict-transport-security": ("high", "HSTS not set — connections may be downgraded to HTTP"),
    "content-security-policy": ("high", "No CSP — increased XSS/data-injection blast radius"),
    "x-frame-options": ("medium", "Clickjacking protection missing (also settable via CSP frame-ancestors)"),
    "x-content-type-options": ("medium", "MIME-sniffing not disabled (set nosniff)"),
    "referrer-policy": ("low", "Referrer-Policy not set — URLs may leak to third parties"),
    "permissions-policy": ("low", "Permissions-Policy not set — browser features not restricted"),
}

# headers that leak stack/version info
_LEAKY_HEADERS = {
    "server": "Reveals server software/version",
    "x-powered-by": "Reveals framework/language",
    "x-aspnet-version": "Reveals ASP.NET version",
    "x-aspnetmvc-version": "Reveals ASP.NET MVC version",
    "x-generator": "Reveals CMS/generator",
    "x-drupal-cache": "Reveals Drupal",
    "via": "Reveals proxy/cache software",
}


@dataclass
class Finding:
    header: str
    severity: str
    detail: str


@dataclass
class HeaderAudit:
    url: str
    status: int | None
    present: dict[str, str] = field(default_factory=dict)
    missing: list[Finding] = field(default_factory=list)
    info_leaks: list[Finding] = field(default_factory=list)
    cookie_issues: list[Finding] = field(default_factory=list)
    grade: str = "?"
    score: int = 0


def _analyze_cookies(result: HttpResult) -> list[Finding]:
    issues: list[Finding] = []
    is_https = (result.final_url or result.url or "").startswith("https")
    for cookie in result.get_all("set-cookie"):
        name = cookie.split("=", 1)[0].strip()
        # Test the ATTRIBUTE names, not a substring of the whole cookie — otherwise
        # a value like `mode=insecure` contains "secure" and masks the missing flag.
        attrs = {seg.strip().split("=", 1)[0].lower() for seg in cookie.split(";")[1:]}
        if is_https and "secure" not in attrs:
            issues.append(Finding(header=f"cookie:{name}", severity="medium",
                                   detail="Cookie without Secure flag over HTTPS"))
        if "httponly" not in attrs:
            issues.append(Finding(header=f"cookie:{name}", severity="low",
                                   detail="Cookie without HttpOnly (readable from JS)"))
        if "samesite" not in attrs:
            issues.append(Finding(header=f"cookie:{name}", severity="low",
                                   detail="Cookie without SameSite (CSRF exposure)"))
    return issues


def audit_headers(result: HttpResult) -> HeaderAudit:
    headers_lc = {k.lower(): v for k, v in result.headers}
    audit = HeaderAudit(url=result.final_url or result.url, status=result.status)

    is_https = (result.final_url or result.url or "").startswith("https")
    max_score = 0
    got = 0
    for header, (severity, explanation) in _SECURITY_HEADERS.items():
        weight = {"high": 3, "medium": 2, "low": 1}[severity]
        # HSTS over plain HTTP is meaningless (browsers ignore it) — don't grade it there,
        # so an http:// endpoint isn't dinged for a header that couldn't help it anyway.
        if header == "strict-transport-security" and not is_https:
            continue
        max_score += weight
        if header in headers_lc:
            audit.present[header] = headers_lc[header]
            got += weight
        else:
            audit.missing.append(Finding(header=header, severity=severity, detail=explanation))

    for header, why in _LEAKY_HEADERS.items():
        if header in headers_lc:
            audit.info_leaks.append(
                Finding(header=header, severity="info", detail=f"{why}: {headers_lc[header]}")
            )

    audit.cookie_issues = _analyze_cookies(result)

    audit.score = round((got / max_score) * 100) if max_score else 0
    audit.grade = (
        "A" if audit.score >= 85 else
        "B" if audit.score >= 70 else
        "C" if audit.score >= 50 else
        "D" if audit.score >= 30 else
        "F"
    )
    return audit
