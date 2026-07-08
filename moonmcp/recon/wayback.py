"""Historical URL discovery via the Internet Archive's Wayback CDX API.

Passive: talks only to web.archive.org, never the target.  Great for surfacing
old endpoints, parameters, and forgotten files that are still live.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import quote

from ..net.http import HttpClient


@dataclass
class WaybackResult:
    domain: str
    urls: list[str] = field(default_factory=list)
    total: int = 0
    error: str | None = None
    interesting: list[str] = field(default_factory=list)


# Extensions/keywords worth flagging when found in archived URLs.
_INTERESTING = (
    ".json", ".xml", ".sql", ".bak", ".old", ".zip", ".tar", ".gz", ".env",
    ".config", ".yml", ".yaml", ".log", ".git", "api/", "admin", "graphql",
    "swagger", "backup", "debug", "token", "key=", "password", "secret",
)


async def fetch_wayback_urls(
    client: HttpClient,
    domain: str,
    *,
    limit: int = 500,
    include_subdomains: bool = True,
) -> WaybackResult:
    domain = domain.strip().lower().lstrip("*.").rstrip(".")
    pattern = f"*.{domain}/*" if include_subdomains else f"{domain}/*"
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={quote(pattern)}&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    r = await client.fetch(url, timeout=30.0, follow_redirects=True)
    result = WaybackResult(domain=domain)
    if r.error or r.status != 200:
        result.error = r.error or f"HTTP {r.status}"
        return result
    try:
        rows = json.loads(r.text())
    except json.JSONDecodeError:
        result.error = "unparseable response"
        return result
    # First row is the header when fl=original is used.
    urls = [row[0] for row in rows[1:] if row]
    seen: set[str] = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    result.urls = deduped
    result.total = len(deduped)
    result.interesting = [
        u for u in deduped if any(tok in u.lower() for tok in _INTERESTING)
    ][:200]
    return result
