"""Email-security posture: SPF, DMARC, DKIM and CAA analysis.

All DNS-based (via the resolver layer, which uses DNS-over-HTTPS when dnspython
isn't installed), so it is passive with respect to the target's own web tier.
Weak or missing SPF/DMARC is a common, reportable spoofing exposure.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..net.dns import resolve

_COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2"]


@dataclass
class EmailSecurity:
    domain: str
    spf: str | None = None
    spf_policy: str | None = None
    dmarc: str | None = None
    dmarc_policy: str | None = None
    dkim_selectors_found: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "?"


def _spf_policy(record: str) -> str:
    for token, name in (("-all", "hard fail"), ("~all", "soft fail"),
                        ("?all", "neutral"), ("+all", "pass (any sender!)")):
        if token in record:
            return name
    return "no all mechanism"


async def analyze_email_security(client, domain: str) -> EmailSecurity:
    domain = domain.strip().lstrip("*.").rstrip(".").lower()
    result = EmailSecurity(domain=domain)

    # SPF (TXT on the apex)
    txt = await resolve(domain, rdtypes=("TXT",), http_client=client)
    for rec in txt.records.get("TXT", []):
        val = rec.strip('"')
        if val.lower().startswith("v=spf1"):
            result.spf = val
            result.spf_policy = _spf_policy(val)
            break
    if not result.spf:
        result.issues.append("No SPF record — domain can be more easily spoofed")
    elif "+all" in (result.spf or ""):
        result.issues.append("SPF uses +all — accepts mail from ANY server (misconfiguration)")
    elif result.spf_policy == "neutral":
        result.issues.append("SPF ends in ?all (neutral) — provides little protection")

    # DMARC (_dmarc TXT)
    dmarc = await resolve(f"_dmarc.{domain}", rdtypes=("TXT",), http_client=client)
    for rec in dmarc.records.get("TXT", []):
        val = rec.strip('"')
        if val.lower().startswith("v=dmarc1"):
            result.dmarc = val
            for part in val.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    result.dmarc_policy = part[2:].strip()
            break
    if not result.dmarc:
        result.issues.append("No DMARC record — spoofed mail is not reported/rejected")
    elif result.dmarc_policy == "none":
        result.issues.append("DMARC p=none — monitoring only; spoofed mail still delivered")

    # DKIM (probe common selectors)
    for selector in _COMMON_DKIM_SELECTORS:
        d = await resolve(f"{selector}._domainkey.{domain}", rdtypes=("TXT", "CNAME"), http_client=client)
        if d.records.get("TXT") or d.records.get("CNAME"):
            result.dkim_selectors_found.append(selector)
    if not result.dkim_selectors_found:
        result.issues.append("No DKIM found on common selectors (may use a custom selector)")

    # CAA (restricts which CAs may issue certs)
    caa = await resolve(domain, rdtypes=("CAA",), http_client=client)
    result.caa = caa.records.get("CAA", [])
    if not result.caa:
        result.issues.append("No CAA record — any CA may issue certificates for this domain")

    # Grade
    score = 0
    if result.spf and "+all" not in result.spf:
        score += 1
    if result.dmarc and result.dmarc_policy in ("quarantine", "reject"):
        score += 2
    elif result.dmarc:
        score += 1
    if result.dkim_selectors_found:
        score += 1
    if result.caa:
        score += 1
    result.grade = ("A" if score >= 5 else "B" if score >= 4 else "C" if score >= 2 else "D" if score >= 1 else "F")
    return result
