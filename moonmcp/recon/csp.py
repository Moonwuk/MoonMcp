"""Content-Security-Policy strength analysis (passive, no traffic).

`audit_headers` grades CSP present-vs-absent, which silently rewards a
worthless-but-present policy. This module parses the policy text and downgrades
the ones that don't actually stop script injection.

The score-reducing weaknesses are the ones that make a CSP *bypassable* for XSS:
``'unsafe-inline'`` (unless neutralised by a nonce/hash), ``'unsafe-eval'``, a
wildcard ``*`` source, ``data:``/``blob:`` script sources, a plaintext ``http:``
source, and — the worst case — no ``script-src`` **or** ``default-src`` at all
(scripts entirely unrestricted). Softer hardening gaps (``object-src`` not locked
down, missing ``base-uri``) are reported but do NOT move the score, so a genuinely
strong policy like ``default-src 'self'`` still grades full marks.

Pure text analysis — no network, no browser. Output feeds
:func:`moonmcp.recon.headers.audit_headers`.
"""

from __future__ import annotations

# The keyword source-expressions that indicate script sources are unrestricted.
_HASH_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def parse_policy(policy: str) -> dict[str, list[str]]:
    """Parse a CSP header value into ``{directive: [source, ...]}`` (pure).

    Directive names are lower-cased; source expressions keep their original case
    (so a nonce/hash value isn't mangled). A repeated directive keeps the first
    occurrence, matching how browsers treat duplicate directives."""

    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        toks = part.split()
        if not toks:
            continue
        name = toks[0].lower()
        if name not in directives:
            directives[name] = toks[1:]
    return directives


def _effective(directives: dict[str, list[str]], name: str) -> list[str] | None:
    """Sources for *name*, falling back to ``default-src`` (CSP fallback rule).

    Returns None only when neither the directive nor ``default-src`` is present
    (``base-uri`` has no fallback, so callers pass ``fallback=False`` there)."""

    if name in directives:
        return directives[name]
    return directives.get("default-src")


def analyze_csp(policy: str) -> dict:
    """Assess a CSP's script-injection strength (pure).

    Returns ``{"strength": float in [0,1], "weaknesses": [(directive, severity,
    detail), ...]}``. ``strength`` is 1.0 for a policy with no bypassable script
    sources and drops as bypasses are found; the caller multiplies the CSP's
    header weight by it. Low-severity hardening findings are listed but never
    reduce ``strength``."""

    directives = parse_policy(policy)
    weaknesses: list[tuple[str, str, str]] = []
    penalty = 0.0

    if "script-src" not in directives and "default-src" not in directives:
        weaknesses.append((
            "script-src", "high",
            "neither script-src nor default-src set — script sources are unrestricted"))
        penalty += 0.5
        script: list[str] = []
        src_dir = "script-src"
    else:
        src_dir = "script-src" if "script-src" in directives else "default-src"
        script = directives.get("script-src", directives.get("default-src", []))

    script_lc = [s.lower() for s in script]
    has_nonce_or_hash = any(s.startswith(_HASH_PREFIXES) for s in script_lc)

    if "'unsafe-inline'" in script_lc:
        if has_nonce_or_hash:
            weaknesses.append((
                src_dir, "info",
                "'unsafe-inline' present but ignored by CSP3 browsers because a "
                "nonce/hash source is also set"))
        else:
            weaknesses.append((
                src_dir, "high",
                "'unsafe-inline' script source — inline-script XSS is not blocked"))
            penalty += 0.5
    if "'unsafe-eval'" in script_lc:
        weaknesses.append((
            src_dir, "high",
            "'unsafe-eval' script source — eval()/Function() injection is not blocked"))
        penalty += 0.3
    if "*" in script_lc:
        weaknesses.append((
            src_dir, "high",
            "wildcard '*' script source — a script may be loaded from any origin"))
        penalty += 0.5
    if any(s in ("data:", "blob:") for s in script_lc):
        weaknesses.append((
            src_dir, "high",
            "data:/blob: script source — a script is injectable via a data URI"))
        penalty += 0.3
    if "http:" in script_lc:
        weaknesses.append((
            src_dir, "medium",
            "http: script source — scripts may be loaded over plaintext (downgrade)"))
        penalty += 0.15

    # Hardening gaps below: reported, but they do NOT reduce strength.
    obj = _effective(directives, "object-src")
    if obj is None:
        weaknesses.append((
            "object-src", "low",
            "no object-src or default-src — plugin/embed sources are unrestricted"))
    else:
        obj_lc = [s.lower() for s in obj]
        if "*" in obj_lc or "http:" in obj_lc:
            weaknesses.append((
                "object-src", "low",
                "object-src (or its default-src fallback) is permissive — prefer 'none'"))
    if "base-uri" not in directives:
        weaknesses.append((
            "base-uri", "low",
            "base-uri not set — an injected <base> tag can hijack relative URLs"))

    strength = max(0.0, round(1.0 - penalty, 3))
    return {"strength": strength, "weaknesses": weaknesses}
