"""Secret / credential detection for web pages and JavaScript.

A curated set of high-precision, prefix-anchored patterns (derived from the
gitleaks / SecretFinder / trufflehog rule corpora) plus a couple of generic
patterns gated by a placeholder denylist and Shannon-entropy check to keep the
false-positive rate down.  Findings are redacted before they leave the process.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from ..net.http import HttpClient

# (name, pattern, fp_risk, capture_group)
_RAW_PATTERNS: list[tuple[str, str, str, int]] = [
    ("AWS Access Key ID", r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b", "low", 1),
    ("AWS Secret Access Key", r"(?i)aws.{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]", "medium", 1),
    ("Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "low", 0),
    ("Google OAuth Token", r"ya29\.[0-9A-Za-z_\-]{20,}", "medium", 0),
    ("Google OAuth Client ID", r"[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "low", 0),
    ("Google OAuth Client Secret", r"GOCSPX-[0-9A-Za-z_\-]{28}", "low", 0),
    ("GitHub PAT", r"ghp_[0-9A-Za-z]{36}", "low", 0),
    ("GitHub OAuth Token", r"gho_[0-9A-Za-z]{36}", "low", 0),
    ("GitHub App Token", r"(?:ghu|ghs)_[0-9A-Za-z]{36}", "low", 0),
    ("GitHub Refresh Token", r"ghr_[0-9A-Za-z]{36}", "low", 0),
    ("GitHub Fine-grained PAT", r"github_pat_[0-9A-Za-z_]{82}", "low", 0),
    ("GitLab PAT", r"glpat-[0-9A-Za-z_\-]{20}", "low", 0),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z]{10,48}", "low", 0),
    ("Slack Webhook", r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}", "low", 0),
    ("Stripe Secret Key", r"(?:sk|rk)_(?:live|test|prod)_[0-9a-zA-Z]{24,99}", "low", 0),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,99}", "low", 0),
    ("Twilio API Key", r"\bSK[0-9a-fA-F]{32}\b", "medium", 0),
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "low", 0),
    ("Mailgun Key", r"\bkey-[0-9a-f]{32}\b", "medium", 0),
    ("Mailchimp API Key", r"\b[0-9a-f]{32}-us[0-9]{1,2}\b", "low", 0),
    ("JSON Web Token", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}", "medium", 0),
    ("Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", "low", 0),
    ("npm Token", r"npm_[0-9A-Za-z]{36}", "low", 0),
    ("Facebook Access Token", r"EAACEdEose0cBA[0-9A-Za-z]+", "low", 0),
    ("Square Access Token", r"(?:sq0atp-|EAAA)[0-9A-Za-z_\-]{22,60}", "low", 0),
    ("Square OAuth Secret", r"sq0csp-[0-9A-Za-z_\-]{43}", "low", 0),
    ("Braintree/PayPal Token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "low", 0),
    ("Cloudinary URL", r"cloudinary://[0-9]{12,}:[0-9A-Za-z_\-]+@[0-9a-z_\-]+", "low", 0),
    ("Shopify Token", r"shp(?:at|ss|pa|ca)_[a-fA-F0-9]{32}", "low", 0),
    ("Telegram Bot Token", r"\b[0-9]{8,10}:[a-zA-Z0-9_\-]{35}\b", "medium", 0),
    ("Postman API Key", r"PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}", "low", 0),
    ("PyPI Upload Token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "low", 0),
    ("DigitalOcean PAT", r"dop_v1_[a-f0-9]{64}", "low", 0),
    ("Databricks PAT", r"\bdapi[a-f0-9]{32}\b", "medium", 0),
    ("New Relic API Key", r"NRAK-[A-Z0-9]{27}", "low", 0),
    ("Linear API Key", r"lin_api_[0-9A-Za-z]{40}", "low", 0),
    ("Age Secret Key", r"AGE-SECRET-KEY-1[0-9A-Z]{58}", "low", 0),
    ("Basic Auth in URL", r"(?i)[a-z][a-z0-9+.\-]+://[^/\s:@]+:([^/\s:@]{3,})@", "high", 1),
    ("Generic Secret Assignment",
     r"(?i)(?:api[_-]?key|secret|token|password|passwd|auth)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_.=]{8,64})['\"]", "high", 1),
]

_PATTERNS = [(name, re.compile(pat), risk, grp) for name, pat, risk, grp in _RAW_PATTERNS]

_PLACEHOLDERS = {
    "xxxxxxxx", "your_api_key", "yourapikey", "changeme", "example", "test",
    "password", "secret", "null", "undefined", "none", "todo", "placeholder",
    "0000000000000000", "1234567890", "abcdefghijklmnop", "api_key", "apikey",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return value[0] + "***"
    return f"{value[:4]}…{value[-4:]} ({len(value)} chars)"


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    if low in _PLACEHOLDERS:
        return True
    return any(p in low for p in ("example", "changeme", "your_", "placeholder", "xxxx"))


@dataclass
class SecretHit:
    type: str
    fp_risk: str
    redacted: str
    context: str
    source: str = ""


@dataclass
class SecretScan:
    scanned_sources: list[str] = field(default_factory=list)
    hits: list[SecretHit] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.hits)


def scan_text(text: str, source: str = "") -> list[SecretHit]:
    hits: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()
    for name, rx, risk, grp in _PATTERNS:
        for m in rx.finditer(text):
            value = m.group(grp) if grp and m.groups() else m.group(0)
            if not value:
                continue
            # Noise gating for the high-FP generic patterns.
            if risk == "high":
                if _looks_placeholder(value) or _shannon_entropy(value) < 3.0:
                    continue
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 25)
            ctx = text[start:m.start() + len(m.group(0)) + 15].replace("\n", " ").strip()
            hits.append(SecretHit(type=name, fp_risk=risk, redacted=_redact(value),
                                  context=ctx[:120], source=source))
    return hits


async def scan_secrets(
    client: HttpClient,
    url: str,
    *,
    scope_check: Callable[[str], bool] | None = None,
    include_js: bool = True,
    max_js: int = 15,
) -> SecretScan:
    from .crawl import _JS_URL_RE, _extract  # reuse link/JS extraction

    scan = SecretScan()
    page = await client.fetch(url, follow_redirects=True, timeout=12.0, scope_check=scope_check)
    if page.status is None:
        scan.errors[url] = page.error or "unreachable"
        return scan
    html = page.text(limit=500_000)
    scan.scanned_sources.append(page.final_url or url)
    scan.hits.extend(scan_text(html, source=page.final_url or url))

    if include_js:
        _, js, _, _ = _extract(page.final_url or url, html)
        # also pick up bare .js references the href extractor may miss
        for jm in _JS_URL_RE.finditer(html):
            from urllib.parse import urljoin
            js.add(urljoin(page.final_url or url, jm.group(1)))
        js_files = [u for u in js if u.lower().split("?")[0].endswith(".js")][:max_js]
        for jurl in js_files:
            if scope_check is not None and not scope_check(jurl):
                continue
            jr = await client.fetch(jurl, follow_redirects=True, timeout=12.0, scope_check=scope_check)
            if jr.status is None or not jr.body:
                continue
            scan.scanned_sources.append(jurl)
            scan.hits.extend(scan_text(jr.text(limit=800_000), source=jurl))
    return scan
