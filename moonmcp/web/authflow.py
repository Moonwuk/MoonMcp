"""Account-takeover flow abuses — the automatable slice of auth-flow testing.

Two of the highest-yield, easiest-to-automate bug classes in bug bounty live in
the OTP / password-reset / email-verification flow, and both are trivially safe
to *detect* (no exploitation — the agent confirms the real-world effect):

* **secret-in-response-body** (GLOBAL-1) — an OTP, 2FA code, password-reset token
  or verification link that the app returns *in-band* (in the JSON/body of the
  request response) instead of delivering out-of-band by email/SMS. Whoever can
  make the request reads the secret → instant ATO. Rife in fintech APIs.
* **password-reset poisoning** (GLOBAL-2) — the reset link's host is built from a
  user-controlled ``Host`` / ``X-Forwarded-Host``. Point it at an attacker host
  and the victim's reset token is delivered there → full ATO, no session needed.

Both are detection-only. The scanner is a pure function so it can be unit-tested
hard; ``token``/``csrf``/OAuth ``access_token`` are deliberately NOT treated as
leaks (those are meant to be in-band).
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..net.http import HttpClient

# ── GLOBAL-1: secret-in-response-body ──────────────────────────────────────────

# Field names that signal an OUT-OF-BAND secret (OTP / reset / verify / activate).
# Deliberately excludes csrf/xsrf tokens and OAuth access/refresh/id tokens — those
# legitimately travel in the response body and would be pure false positives.
_SECRET_FIELD_RE = re.compile(
    r'["\']?('
    r'otp(?:_?code)?|otc|one[_-]?time[_-]?(?:code|password|pin)|'
    r'(?:2fa|mfa|two[_-]?factor)[_-]?(?:code|token|otp)?|'
    r'(?:verification|verify|activation|activate|confirmation|confirm|recovery|'
    r'recover|unlock|magic|invite|invitation|signup)[_-]?(?:code|token|link|url|key)|'
    r'password[_-]?reset[_-]?(?:token|code|link|url|key)|'
    r'reset[_-]?(?:token|code|link|url|key)|'
    r'(?:security|auth)[_-]?(?:code|pin)|'
    r'pin(?:[_-]?code)?'
    r')["\']?\s*[:=]\s*["\']?'
    r'([A-Za-z0-9][^"\'\s,}\])&]{3,})',
    re.I)

# Values that match the shape but are not secrets (status words, nulls).
_FIELD_STOPWORDS = frozenset({
    "null", "none", "true", "false", "undefined", "sent", "success", "ok",
    "pending", "enabled", "disabled", "required", "expired", "invalid", "empty",
})

# A reset / verify / magic link (token-bearing URL) anywhere in the body.
_LINK_RE = re.compile(
    r'https?://[^\s"\'<>]*?'
    r'(?:reset[_-]?password|password[_-]?reset|/reset|verify|confirm|activate|'
    r'set[_-]?password|token=|otp=|code=|magic)'
    r'[^\s"\'<>]*',
    re.I)

# Only hunt bare numeric codes when the body clearly talks about an OTP.
_OTP_CONTEXT_RE = re.compile(
    r'one[\s_-]?time|\botp\b|\bpasscode\b|\bpin\b|verification code|security code|'
    r'2fa|two[\s_-]?factor|your code|access code|auth code', re.I)
# A standalone 4–8 digit run — not glued to letters, other digits, or a decimal
# point (so digits embedded in a longer token like `abcdef123456` don't match).
_BARE_CODE_RE = re.compile(r'(?<![\w.])(\d{4,8})(?![\w.])')


def _redact(value: str) -> str:
    """Mask the middle of a secret so evidence is safe to log/store."""

    v = value.strip().strip('"\'')
    if len(v) <= 4:
        return v[0] + "*" * (len(v) - 1) if v else ""
    if len(v) <= 8:
        return f"{v[:2]}{'*' * (len(v) - 4)}{v[-2:]}"
    return f"{v[:4]}…{v[-4:]}"


def scan_response_leak(text: str) -> list[dict]:
    """Scan a response body for out-of-band secrets returned *in-band*.

    Returns findings for: named OTP/reset/verify fields carrying a value
    (``confirmed``), token-bearing reset/verify links (``confirmed``), and — only
    when the body talks about an OTP — bare numeric codes (``review``, lower
    confidence). Pure function; capped input.
    """

    text = text[:200_000]
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    captured: set[str] = set()  # raw secret values already reported (dedup bare codes)

    for m in _SECRET_FIELD_RE.finditer(text):
        field, value = m.group(1), m.group(2)
        if value.lower() in _FIELD_STOPWORDS or value.isalpha() and len(value) < 6:
            continue
        key = ("field", f"{field.lower()}={value}")
        if key in seen:
            continue
        seen.add(key)
        captured.add(value)
        findings.append({
            "kind": "secret_in_body", "field": field, "sample": _redact(value),
            "severity": "high", "verdict": "confirmed",
            "detail": f"field '{field}' returns a secret value in the response body — an OTP / "
                      "reset / verification secret must be delivered out-of-band (email/SMS), not "
                      "in-band; whoever triggers the flow reads it → account takeover",
        })

    for m in _LINK_RE.finditer(text):
        link = m.group(0)
        key = ("link", link)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "kind": "reset_link_in_body", "sample": _redact(link),
            "severity": "high", "verdict": "confirmed",
            "detail": "a reset/verification link is returned in the response body — the token that "
                      "should reach the user out-of-band is exposed in-band → account takeover",
        })

    if _OTP_CONTEXT_RE.search(text):
        for m in _BARE_CODE_RE.finditer(text):
            code = m.group(1)
            key = ("code", code)
            if key in seen or code in captured:
                continue
            seen.add(key)
            findings.append({
                "kind": "otp_code_in_body", "sample": _redact(code),
                "severity": "medium", "verdict": "review",
                "detail": f"a standalone {len(code)}-digit code appears in an OTP-context response "
                          "body — likely an in-band one-time code; confirm it is the real OTP",
            })
            if sum(1 for f in findings if f["kind"] == "otp_code_in_body") >= 3:
                break

    return findings


async def probe_response_leak(client: HttpClient, url: str, *, method: str = "GET",
                              body: bytes | None = None,
                              headers: dict[str, str] | None = None,
                              scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Drive one request at a flow endpoint (OTP/reset/verify) and scan its
    response for in-band secrets. The agent supplies the endpoint + any body
    (e.g. the account's email) that triggers the flow."""

    r = await client.fetch(url, method=method.upper(), body=body, headers=headers,
                           follow_redirects=False, timeout=12.0, scope_check=scope_check)
    if r.status is None:
        return []
    return scan_response_leak(r.text(limit=200_000))


# ── GLOBAL-2: password-reset poisoning ─────────────────────────────────────────

# Headers a reverse proxy / framework may trust to build the public base URL.
POISON_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-Host",
    "X-Forwarded-For-Host", "Forwarded", "Host",
]


def _poison_value(header: str, canary_host: str) -> str:
    """The header value carrying the canary (``Forwarded`` has its own syntax)."""

    return f"host={canary_host}" if header.lower() == "forwarded" else canary_host


def assess_reflection(text: str, location: str, canary_host: str) -> bool:
    """Did the poisoned host value come back in the body or the redirect Location?"""

    needle = canary_host.lower()
    return needle in (text or "").lower() or needle in (location or "").lower()


async def probe_reset_poison(client: HttpClient, url: str, canary_host: str, *,
                             method: str = "POST", body: bytes | None = None,
                             headers: dict[str, str] | None = None,
                             scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Send the reset request once per poisoning header set to *canary_host*; flag
    the ones reflected in the response body / ``Location`` — a signal the reset
    link is built from a user-controlled host. Use an OAST host as *canary_host*
    to also catch server-side host fetches. The connection still targets *url*'s
    real (in-scope) host; only the header is poisoned."""

    findings: list[dict] = []
    for h in POISON_HEADERS:
        extra = dict(headers or {})
        extra[h] = _poison_value(h, canary_host)
        r = await client.fetch(url, method=method.upper(), body=body, headers=extra,
                               follow_redirects=False, timeout=12.0, scope_check=scope_check)
        if r.status is None:
            continue
        loc = r.header("location") or ""
        if assess_reflection(r.text(limit=100_000), loc, canary_host):
            where = "location" if canary_host.lower() in loc.lower() else "body"
            findings.append({
                "kind": "reset_poison", "header": h, "canary": canary_host, "where": where,
                "severity": "high", "verdict": "review",
                "detail": f"the '{h}' value ({canary_host}) is reflected in the response {where} — "
                          "if the password-reset email's link is built from this host, the reset "
                          "token is delivered to an attacker-controlled host (full ATO). Confirm by "
                          "reading the actual reset email, or use an OAST canary to catch a fetch",
            })
    return findings
