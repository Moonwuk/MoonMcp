"""Unicode-normalization bypass probe — detection only.

A WAF / input validator inspects the **raw request bytes**, but the app behind it often
**normalizes** that input afterwards (Unicode NFKC, or ASCII case-folding, or a legacy
"best-fit" charset mapping). When the two disagree, a character that is harmless to the
filter collapses into a dangerous ASCII one on the server — e.g. the fullwidth ``＜`` (U+FF1C)
NFKC-normalizes to ``<``, so a WAF that blocks ``<script>`` never sees the ``<`` while the app
does. This normalization step is the primitive behind a large family of filter bypasses
(fullwidth XSS, ``ſ``→``s`` keyword smuggling, Kelvin-sign ``K``→``k`` case folding).

This module supplies benign, inert **canary-wrapped** test characters + pure analysers; the
``unicode_bypass_probe`` server tool injects them into one reflective parameter and scores.
Each payload is a single test char wrapped in a unique alphanumeric canary
(``<canary><char><canary>``) and delivers **nothing executable** — the signal is purely
*which form the app reflected*: the normalized ASCII form appearing **between the canaries**
(where we sent only the raw Unicode char) proves the server applied the transform, exactly
like a parser-differential decode lane. Never a live payload, never data extraction.

* **dangerous** vectors (``＜＞＂＇／＼（；．`` → ``< > " ' / \\ ( ; .``) normalize to
  filter-sensitive punctuation — a real XSS / injection / traversal WAF-bypass primitive →
  **strong** signal.
* **keyword** vectors (``ſ``→``s``, ligature ``ﬀ``→``ff``, Kelvin ``K``→``k``) normalize to
  letters — proof the server folds input, so a blocklisted keyword (``script``, ``select``)
  can be smuggled in a normalize-equivalent form → **medium** signal.

Detection-only: turning a confirmed normalization into a live bypass payload is Strix's job.
Sources: unicode.org/reports/tr36 (security), tr39 (confusables),
https://portswigger.net/research (Unicode normalization). See docs/RESEARCH_GAPS.md Theme 6.
"""

from __future__ import annotations

import html
import unicodedata
from dataclasses import dataclass

from .inject import with_param

# Inert, alphanumeric, markup-free canary — NFKC- and casefold-invariant (plain ASCII), so it
# frames the injected char without itself being transformed. A reflection of `<canary><ascii>
# <canary>` proves the app placed that ascii char where we sent a raw Unicode one.
CANARY = "moonub7qz"


@dataclass(frozen=True)
class Vec:
    """One normalization test char. *raw* is the Unicode char we send; *norm* is the ASCII it
    collapses to under *kind* (``nfkc`` or ``casefold``); *dangerous* marks a filter-sensitive
    target (punctuation) vs a keyword-only one (a letter)."""

    name: str
    raw: str
    norm: str
    kind: str          # "nfkc" | "casefold"
    dangerous: bool


# Verified against Python's unicodedata (see the import-time assertion below). NFKC covers the
# fullwidth/ligature/long-s collapses; Kelvin U+212A is NFKC-stable and folds only under
# casefold, so it uniquely detects an app that case-folds without NFKC.
VECTORS: list[Vec] = [
    Vec("fullwidth_lt", "＜", "<", "nfkc", True),
    Vec("fullwidth_gt", "＞", ">", "nfkc", True),
    Vec("fullwidth_dquote", "＂", '"', "nfkc", True),
    Vec("fullwidth_squote", "＇", "'", "nfkc", True),
    Vec("fullwidth_slash", "／", "/", "nfkc", True),
    Vec("fullwidth_backslash", "＼", "\\", "nfkc", True),
    Vec("fullwidth_lparen", "（", "(", "nfkc", True),
    Vec("fullwidth_semicolon", "；", ";", "nfkc", True),
    Vec("fullwidth_dot", "．", ".", "nfkc", True),
    Vec("longs_to_s", "ſ", "s", "nfkc", False),
    Vec("ligature_ff", "ﬀ", "ff", "nfkc", False),
    Vec("kelvin_to_k", "K", "k", "casefold", False),
]


def _transform(raw: str, kind: str) -> str:
    return unicodedata.normalize("NFKC", raw) if kind == "nfkc" else raw.casefold()


# Fail fast if a future Unicode/Python revision changes a mapping — better a broken import in
# CI than a silently-wrong detector in the field.
for _v in VECTORS:
    assert _transform(_v.raw, _v.kind) == _v.norm, _v.name        # noqa: S101
    assert _v.raw != _v.norm                                       # noqa: S101


def probe_value(vec: Vec) -> str:
    """The inert value we inject for *vec*: the raw Unicode char wrapped in the canary."""

    return f"{CANARY}{vec.raw}{CANARY}"


def baseline_value() -> str:
    """An all-ASCII canary-wrapped marker to test whether the endpoint reflects input at all."""

    return f"{CANARY}z{CANARY}"


def norm_forms(vec: Vec) -> list[str]:
    """Every way the *normalized* char could be reflected between the canaries: the raw ASCII
    plus its HTML-entity encodings (named / decimal / hex), so an app that normalizes AND
    output-encodes (``＜`` → ``<`` → ``&lt;``) is still detected — the normalization already
    happened server-side. Multi-char norms (``ff``) have no entity form."""

    forms = [vec.norm]
    if len(vec.norm) == 1:
        cp = ord(vec.norm)
        forms += [html.escape(vec.norm, quote=True), f"&#{cp};", f"&#x{cp:x};", f"&#x{cp:X};"]
    # dedup, preserve order
    seen: dict[str, None] = {}
    for f in forms:
        seen.setdefault(f, None)
    return list(seen)


def raw_marker(vec: Vec) -> str:
    """The passthrough tell: the raw Unicode char still sitting between the canaries."""

    return f"{CANARY}{vec.raw}{CANARY}"


def norm_markers(vec: Vec) -> list[str]:
    """The normalization tells: a normalized form between the canaries."""

    return [f"{CANARY}{f}{CANARY}" for f in norm_forms(vec)]


def is_reflective(baseline_body: str) -> bool:
    """Does the endpoint echo our canary at all? (pure)"""

    return CANARY in (baseline_body or "")


def assess_vector(vec: Vec, body: str) -> dict | None:
    """Score one vector's response (pure). A hit requires the *normalized* form to appear
    between the canaries while the *raw* form does NOT — the app transformed our injected
    Unicode char into ASCII. Requiring the raw form's absence excludes a passthrough echo, and
    the canary framing means a normalized marker can only come from our injected char (chance
    can't place ``<canary><norm><canary>`` — the request carried ``<canary><raw><canary>``).

    Matching is **case-sensitive on purpose**: lowercasing the body would itself case-fold
    (e.g. Kelvin U+212A ``.lower()`` → ``k``), turning a passthrough echo of the raw char into a
    false normalization hit. The case change *is* the signal for case-fold vectors."""

    b = body or ""
    if raw_marker(vec) in b:
        return None                                    # passthrough — app did not normalize
    hit_form = next((m for m in norm_markers(vec) if m in b), None)
    if hit_form is None:
        return None
    return {
        "vector": vec.name,
        "raw": f"U+{ord(vec.raw):04X}" if len(vec.raw) == 1 else vec.raw,
        "normalized_to": vec.norm,
        "transform": "NFKC" if vec.kind == "nfkc" else "case-fold",
        "severity": "high" if vec.dangerous else "medium",
        "detail": (
            f"'{vec.raw}' was reflected as '{vec.norm}' between our canaries — the server "
            f"applies {'NFKC' if vec.kind == 'nfkc' else 'case-fold'} normalization, so a "
            f"filter that blocks '{vec.norm}' can be bypassed by sending '{vec.raw}'. "
            "Weaponize the bypass via Strix"),
    }


def payloads() -> list[str]:
    """The inert per-vector values for a dry-run preview (pure)."""

    return [probe_value(v) for v in VECTORS]


async def probe_unicode(client, url: str, *, param: str = "q", method: str = "GET",
                        scope_check=None) -> dict:
    """Drive the reflection-based normalization differential against *url*'s *param*. First a
    baseline request checks the endpoint echoes our canary; if not, returns ``reflective=False``
    (the reflection lane can't run). Then one request per vector, each assessed independently.
    Sends only inert canary-wrapped chars; reads and compares reflections. GET query / POST form
    per *method*."""

    m = method.upper()

    async def _reflect(value: str) -> str:
        u, b = with_param(url, param, value, m)
        r = await client.fetch(u, method=m, body=b, follow_redirects=False, scope_check=scope_check)
        return r.text(50_000) if r.status is not None else ""

    baseline = await _reflect(baseline_value())
    if not is_reflective(baseline):
        return {"target": url, "param": param, "method": m, "reflective": False,
                "findings": [], "dangerous": False}

    findings: list[dict] = []
    for vec in VECTORS:
        hit = assess_vector(vec, await _reflect(probe_value(vec)))
        if hit:
            findings.append(hit)
    return {"target": url, "param": param, "method": m, "reflective": True,
            "findings": findings, "dangerous": any(f["severity"] == "high" for f in findings)}
