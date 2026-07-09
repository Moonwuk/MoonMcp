"""Deep endpoint extraction from JavaScript / HTML (LinkFinder-style).

Bundled JS is where a modern SPA's real API surface lives — routes and endpoints
that are never reachable by crawling the UI.  This pulls absolute and relative
endpoints out of a page and its scripts, and flags source maps (``.map``) that
reconstruct the original source.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

# Endpoint-ish strings inside quotes/backticks: full URLs, rooted paths, filenames.
_ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)(
        (?:[a-zA-Z][a-zA-Z0-9+.\-]{1,9}://|//)[\w.\-]+\.[a-zA-Z]{2,}[^"'`\s<>]{0,200}
        |
        /[\w\-./]{2,}(?:\?[^"'`\s<>]{0,160})?
        |
        [\w\-./]{2,}\.(?:php|asp|aspx|jsp|json|xml|action|do|api|graphql)(?:\?[^"'`\s<>]{0,160})?
    )(?:"|'|`)""",
    re.VERBOSE,
)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_SOURCEMAP_RE = re.compile(r"sourceMappingURL=([^\s\"'*]+)", re.IGNORECASE)

# Static-asset / noise extensions we don't treat as endpoints.
_ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
              ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".map")


def _looks_useful(ep: str) -> bool:
    e = ep.strip()
    if len(e) < 3 or e.startswith(("data:", "mailto:", "tel:", "javascript:", "#")):
        return False
    low = e.split("?", 1)[0].lower()
    if low.endswith(_ASSET_EXT):
        return False
    if not re.search(r"[a-zA-Z]", e):
        return False
    return True


def extract_endpoints(text: str, max_results: int = 400) -> list[str]:
    """Return unique endpoint-ish strings found in *text* (JS or HTML)."""

    seen: dict[str, None] = {}
    for m in _ENDPOINT_RE.finditer(text or ""):
        ep = m.group(1).strip()
        if _looks_useful(ep) and ep not in seen:
            seen[ep] = None
            if len(seen) >= max_results:
                break
    return list(seen)


def extract_source_maps(text: str) -> list[str]:
    return list(dict.fromkeys(m.group(1).strip() for m in _SOURCEMAP_RE.finditer(text or "")))


def script_srcs(html: str) -> list[str]:
    return list(dict.fromkeys(m.group(1).strip() for m in _SCRIPT_SRC_RE.finditer(html or "")))


async def analyze(http_client, url: str, *, max_scripts: int = 15, scope_check=None) -> dict:
    """Fetch a page + its scripts and extract endpoints and source maps."""

    page = await http_client.fetch(url, method="GET", follow_redirects=True, scope_check=scope_check)
    if page.status is None:
        return {"url": url, "error": page.error or "failed to fetch page"}
    html = page.text()
    endpoints: dict[str, None] = dict.fromkeys(extract_endpoints(html))
    source_maps: list[dict] = []
    scripts_analysed: list[dict] = []

    base = page.final_url or url
    srcs = script_srcs(html)
    # only follow same-origin scripts (in-scope); cap the count
    try:
        origin = urlsplit(base).hostname
    except ValueError:
        origin = None
    to_fetch = []
    for s in srcs:
        # a malformed src (e.g. an unclosed IPv6 bracket) must not abort the whole
        # analysis and discard the endpoints already found in the page HTML.
        try:
            full = urljoin(base, s)
            if urlsplit(full).hostname == origin:
                to_fetch.append(full)
        except ValueError:
            continue
    for js_url in to_fetch[:max_scripts]:
        r = await http_client.fetch(js_url, method="GET", follow_redirects=True,
                                    scope_check=scope_check)
        if r.status is None or not r.body:
            continue
        body = r.text()
        eps = extract_endpoints(body)
        for e in eps:
            endpoints.setdefault(e, None)
        maps = extract_source_maps(body)
        for mp in maps:
            source_maps.append({"script": js_url, "map": urljoin(js_url, mp)})
        scripts_analysed.append({"url": js_url, "endpoints_found": len(eps),
                                 "has_source_map": bool(maps)})

    return {
        "url": base,
        "scripts_found": len(srcs),
        "scripts_analysed": scripts_analysed,
        "endpoint_count": len(endpoints),
        "endpoints": list(endpoints),
        "source_maps": source_maps,
    }
