"""Web cache deception detection (distinct from cache *poisoning*).

Cache deception tricks the cache into storing a victim's **authenticated** response
under an attacker-readable key, via a URL-parser discrepancy between the CDN and the
origin (BH-USA-2024 "Gotta cache 'em all"): append a static-looking suffix
(``/x.css``), a delimiter (``;x.css``), or an encoded-traversal to a cached static
dir, and the edge caches the private page.

Safe detection = you only ever cache and re-read YOUR OWN data: request the private
page through a crafted variant while authenticated, then re-request the *same*
variant with NO credentials — if the cookieless response returns the private-sized
body (and, best, carries a cache-HIT header) the private page was cached publicly.
Reuses :func:`moonmcp.web.probes.cacheable` to read the HIT headers.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from ..net.http import HttpClient
from .probes import cacheable

# Static-looking suffixes that commonly hit a CDN "cache by extension / path" rule
# while the origin still resolves them to the private page.
_VARIANTS = ("/wcd.css", "/wcd.js", ";wcd.css", "%2fwcd.js", "/%2e%2e/wcd.css")


@dataclass
class CacheDeceptionResult:
    url: str
    vulnerable: bool = False
    baseline: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    error: str | None = None


def deception_variants(url: str) -> list[tuple[str, str]]:
    """Given a private URL, return ``(label, variant_url)`` path-confusion variants."""

    s = urlsplit(url)
    base = (s.path or "/").rstrip("/")
    out: list[tuple[str, str]] = []
    for suf in _VARIANTS:
        out.append((suf, urlunsplit((s.scheme, s.netloc, base + suf, "", ""))))
    return out


def assess_variant(*, auth_len: int, anon_len: int, var_status: int | None,
                   var_len: int, var_headers: dict[str, str]) -> dict | None:
    """Decide whether a cookieless variant response leaked the private page.

    Conservative: the cookieless variant must be a 200 whose size matches the
    authenticated (private) body and does NOT match the anonymous (public) body —
    i.e. an unauthenticated client received the private page. A cache-HIT header
    upgrades it from a candidate to a confirmed deception.
    """

    if var_status != 200:
        return None
    private_like = abs(var_len - auth_len) <= max(64, auth_len // 20)
    public_like = abs(var_len - anon_len) <= max(16, anon_len // 20)
    if not (private_like and not public_like):
        return None
    hit, reasons = cacheable(var_headers)
    return {
        "verdict": "confirmed" if hit else "candidate",
        "severity": "high" if hit else "medium",
        "cached": hit,
        "cache_reasons": reasons,
        "variant_len": var_len,
    }


async def probe_cache_deception(client: HttpClient, url: str, *,
                                scope_check: Callable[[str], bool] | None = None
                                ) -> CacheDeceptionResult:
    """Probe *url* (a private, authenticated page) for web cache deception."""

    result = CacheDeceptionResult(url=url)
    auth = await client.fetch(url, follow_redirects=True, timeout=12.0, scope_check=scope_check)
    anon = await client.fetch(url, follow_redirects=True, timeout=12.0,
                              suppress_auth=True, scope_check=scope_check)
    if auth.status != 200:
        result.error = f"the private URL did not return an authenticated 200 (got {auth.status}) — " \
                       "set engagement auth (auth_set) and pass a page that requires login"
        return result
    auth_len, anon_len = len(auth.body), len(anon.body)
    result.baseline = {"auth_status": auth.status, "auth_len": auth_len,
                       "anon_status": anon.status, "anon_len": anon_len}
    # Need a real authed-vs-anon difference to reason about a "leak".
    if abs(auth_len - anon_len) < 32 and auth.status == anon.status:
        result.error = "no difference between the authed and anonymous response — the page " \
                       "isn't access-controlled, so cache deception can't be assessed"
        return result

    for label, variant in deception_variants(url):
        if scope_check is not None and not scope_check(variant):
            continue
        # Prime the cache as the authenticated user, then read it back cookieless.
        await client.fetch(variant, follow_redirects=True, timeout=12.0, scope_check=scope_check)
        leaked = await client.fetch(variant, follow_redirects=True, timeout=12.0,
                                    suppress_auth=True, scope_check=scope_check)
        hit = assess_variant(auth_len=auth_len, anon_len=anon_len, var_status=leaked.status,
                             var_len=len(leaked.body), var_headers=leaked.headers_map())
        if hit is not None:
            result.findings.append({"variant": variant, "label": label, **hit})
            if hit["verdict"] == "confirmed":
                result.vulnerable = True
    return result
