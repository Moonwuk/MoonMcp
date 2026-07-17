"""Web cache poisoning — unkeyed-input reflection with STATEFUL cache-hit confirmation.

An unkeyed header (``X-Forwarded-Host``, ``X-Forwarded-Scheme``, …) is not part of the cache
key but can change the response (a reflected absolute URL, a redirect). If such a response is
cached, a single request with a malicious unkeyed header poisons the entry and every later
victim is served the poisoned copy. The old heuristic stopped at "reflected AND looks
cacheable" (a soft ``likely``); this module adds the **confirming differential**:

* poison a *throwaway cache-buster key* (``?cb=<random>``) with a benign canary in the unkeyed
  header, then
* send a **clean** request to the same key — if it comes back carrying the canary, the response
  was served **from cache**. Near-zero FP: the clean request never sent the canary, and the
  cache-buster token is a *separate* random (so it can't be the source of the reflection), so
  the canary can only come from the cache.

The cache-buster confines any poisoning to a key no real user requests, and the canary is an
inert domain string. Weaponizing a confirmed vector (an XSS/redirect via the unkeyed value,
poisoning the *real* key) is Strix's job.

Source: PortSwigger "Practical Web Cache Poisoning" (James Kettle).
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from .probes import CACHE_HEADERS, cacheable

# Unkeyed headers to test — the shared probes.CACHE_HEADERS set plus two more high-signal ones.
UNKEYED_HEADERS: list[str] = list(dict.fromkeys(
    CACHE_HEADERS + ["X-Forwarded-Proto", "X-Forwarded-Prefix"]))

# Response headers whose VALUE commonly carries a reflected unkeyed input (a redirect / link).
_REFLECT_HEADERS = ("location", "content-location", "link", "refresh",
                    "access-control-allow-origin", "set-cookie")


def canary_value(canary: str) -> str:
    """A benign domain-shaped payload for the canary — obvious if it lands in a URL (pure)."""

    return f"{canary}.moon.example"


def with_cache_buster(url: str, token: str) -> str:
    """Append ``cb=<token>`` so a poisoned entry lands on a throwaway key, not the real page.
    *token* must NOT contain the canary, or a query-reflecting app would look self-confirming (pure)."""

    sp = urlsplit(url)
    q = f"{sp.query}&cb={token}" if sp.query else f"cb={token}"
    return urlunsplit(sp._replace(query=q))


def _lc(headers_map: dict) -> dict:
    return {k.lower(): v for k, v in (headers_map or {}).items()}


def reflects_canary(canary: str, body: str, headers_map: dict) -> bool:
    """Is the canary reflected in the body or a response-header value? (pure)"""

    if canary in (body or ""):
        return True
    lc = _lc(headers_map)
    return any(canary in (lc.get(h) or "") for h in _REFLECT_HEADERS)


def is_keyed(header: str, headers_map: dict) -> bool:
    """Does the response's ``Vary`` mark *header* (or ``*``) as part of the cache key? Then the
    unkeyed-input premise fails and it can't poison shared entries (pure)."""

    toks = {t.strip().lower() for t in _lc(headers_map).get("vary", "").split(",")}
    return "*" in toks or header.lower() in toks


def cache_hit_signals(headers_map: dict) -> list[str]:
    """Evidence the response was served FROM a cache (Age / X-Cache / CF-Cache-Status) (pure)."""

    lc = _lc(headers_map)
    return [f"{h}: {lc[h]}" for h in ("age", "x-cache", "cf-cache-status", "x-varnish",
                                      "x-cache-hits") if h in lc]


async def probe_cache_poison(client, url: str, *, canary: str, buster: str, scope_check=None) -> dict:
    """Drive the unkeyed-input → cache-hit differential. *canary* and *buster* are independent
    unique tokens (the buster must not contain the canary)."""

    cval = canary_value(canary)

    async def _get(u, headers=None):
        r = await client.fetch(u, headers=headers, follow_redirects=False, scope_check=scope_check)
        if r.status is None:
            return "", {}
        hmap = r.headers_map() if hasattr(r, "headers_map") else {}
        return r.text(200_000), hmap

    _, base_headers = await _get(url)
    base_cacheable, base_reasons = cacheable(base_headers)

    findings: list[dict] = []
    for i, h in enumerate(UNKEYED_HEADERS):
        if is_keyed(h, base_headers):
            continue
        key_url = with_cache_buster(url, f"{buster}{i}")
        a_body, a_headers = await _get(key_url, headers={h: cval})   # A: poison the throwaway key
        if not reflects_canary(canary, a_body, a_headers):
            continue
        a_cacheable, _ = cacheable(a_headers)
        b_body, b_headers = await _get(key_url)                       # B: clean request, same key
        confirmed = reflects_canary(canary, b_body, b_headers)
        findings.append({
            "header": h, "reflected": True, "confirmed": confirmed,
            "cacheable": a_cacheable,
            "severity": "high" if confirmed else "medium",
            "cache_signals": cache_hit_signals(b_headers) if confirmed else None,
            "detail": (
                f"unkeyed `{h}` is reflected AND a clean request to the same cache key returned "
                "our canary — the poisoned response is served from cache (cache poisoning). "
                "Weaponize the unkeyed value (XSS / redirect) via Strix" if confirmed else
                f"unkeyed `{h}` is reflected" + (
                    " and the response looks cacheable — likely cache poisoning (no cache hit "
                    "confirmed on the buster key)" if a_cacheable else
                    " but the response did not look cacheable — host-header injection lead")),
        })

    if any(f["confirmed"] for f in findings):
        verdict = "confirmed"
    elif any(f["cacheable"] for f in findings):
        verdict = "likely"
    elif findings:
        verdict = "inconclusive"
    else:
        verdict = "unconfirmed"

    return {"target": url, "verdict": verdict, "findings": findings,
            "cacheable": base_cacheable, "cache_signals": base_reasons,
            "unkeyed_reflection": [{"header": f["header"], "reflected_canary": canary}
                                   for f in findings]}
