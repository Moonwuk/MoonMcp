"""Active differential probes for high-payout vulnerability classes.

Detection-oriented (not weaponised): each probe sends the smallest benign marker
that *proves the class* and diffs against a control, so the verdict is evidence,
not a guess. Payload data + pure analysers live here; the async orchestration
(fetch baseline + tests, poll OAST) lives in the server tools, which feed the
signals into :func:`moonmcp.confirm.evaluate`.
"""

from __future__ import annotations

import re

# --- SSTI: arithmetic that only renders if the input hits a template engine ---
# 7331*7 = 51317 — a value unlikely to appear on a page by chance. If the result
# shows up (and the literal payload does not), the expression was evaluated.
SSTI_EXPECTED = "51317"
SSTI_PAYLOADS: list[tuple[str, str]] = [
    ("Jinja2/Twig", "{{7331*7}}"),
    ("Freemarker/JSP-EL", "${7331*7}"),
    ("ERB/JSP-scriptlet", "<%= 7331*7 %>"),
    ("Smarty", "{7331*7}"),
    ("Velocity", "#set($m=7331*7)$m"),
    ("Razor", "@(7331*7)"),
    ("Handlebars/other", "#{7331*7}"),
]

# --- SQLi: benign boolean pair + an error trigger (no data extraction) ---
SQLI_ERROR = "'"
SQLI_TRUE = "1' AND '1'='1"
SQLI_FALSE = "1' AND '1'='2"

# --- Cache poisoning: unkeyed headers that frameworks often reflect ---
CACHE_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Server",
    "X-Host", "X-Forwarded-Port", "X-Original-URL", "X-Rewrite-URL",
]
_CACHE_HIT_HEADERS = ("x-cache", "cf-cache-status", "x-drupal-cache",
                      "x-varnish", "age", "x-cache-hits")


# Match the result on digit boundaries so a longer digit run (an epoch, an ID)
# containing "51317" doesn't count as an evaluation.
_SSTI_RE = re.compile(r"(?<!\d)" + re.escape(SSTI_EXPECTED) + r"(?!\d)")


def ssti_findings(baseline_body: str, tested: list[tuple[str, str, str]]) -> list[dict]:
    """Given ``(engine, payload, response_body)`` triples, return the engines whose
    arithmetic was **evaluated** — the result appears (on digit boundaries), the
    literal payload does NOT (so it's rendering, not reflection), and the same
    result isn't already present in the baseline."""

    if _SSTI_RE.search(baseline_body):
        return []  # the marker occurs naturally on the page — can't distinguish
    out: list[dict] = []
    for engine, payload, body in tested:
        if _SSTI_RE.search(body) and payload not in body:
            out.append({"engine": engine, "payload": payload, "evaluated_to": SSTI_EXPECTED})
    return out


def cacheable(headers_map: dict[str, str]) -> tuple[bool, list[str]]:
    """Heuristic: does the response look cacheable/served-from-cache?

    Cache-Control is parsed numerically: ``max-age=0`` / ``s-maxage=0`` /
    ``no-cache`` / ``no-store`` / ``private`` are NOT cacheable. A cache-hit header
    (Age, X-Cache, …) still counts — it proves the response was served from a cache.
    """

    reasons: list[str] = []
    lower = {k.lower(): v for k, v in headers_map.items()}
    cc = lower.get("cache-control", "").lower()
    if "no-store" not in cc and "no-cache" not in cc and "private" not in cc:
        ma = re.search(r"\bmax-age=(\d+)", cc)
        sma = re.search(r"\bs-maxage=(\d+)", cc)
        positive_age = (ma is not None and int(ma.group(1)) > 0) or \
                       (sma is not None and int(sma.group(1)) > 0)
        if "public" in cc or positive_age:
            reasons.append(f"Cache-Control: {cc}")
    for h in _CACHE_HIT_HEADERS:
        if h in lower:
            reasons.append(f"{h}: {lower[h]}")
    return (bool(reasons), reasons)
