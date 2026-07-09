"""Active differential probes for high-payout vulnerability classes.

Detection-oriented (not weaponised): each probe sends the smallest benign marker
that *proves the class* and diffs against a control, so the verdict is evidence,
not a guess. Payload data + pure analysers live here; the async orchestration
(fetch baseline + tests, poll OAST) lives in the server tools, which feed the
signals into :func:`moonmcp.confirm.evaluate`.
"""

from __future__ import annotations

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


def ssti_findings(baseline_body: str, tested: list[tuple[str, str, str]]) -> list[dict]:
    """Given ``(engine, payload, response_body)`` triples, return the engines whose
    arithmetic was evaluated (result present in the response, absent in baseline)."""

    out: list[dict] = []
    base_has = SSTI_EXPECTED in baseline_body
    for engine, payload, body in tested:
        if SSTI_EXPECTED in body and not base_has:
            out.append({"engine": engine, "payload": payload, "evaluated_to": SSTI_EXPECTED})
    return out


def cacheable(headers_map: dict[str, str]) -> tuple[bool, list[str]]:
    """Heuristic: does the response look cacheable/served-from-cache?"""

    reasons: list[str] = []
    lower = {k.lower(): v for k, v in headers_map.items()}
    cc = lower.get("cache-control", "").lower()
    if "public" in cc or "max-age" in cc or "s-maxage" in cc:
        if "no-store" not in cc and "private" not in cc:
            reasons.append(f"Cache-Control: {cc}")
    for h in _CACHE_HIT_HEADERS:
        if h in lower:
            reasons.append(f"{h}: {lower[h]}")
    return (bool(reasons), reasons)
