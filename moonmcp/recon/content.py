"""Active content discovery against a target host.

Two capabilities:
* :func:`fetch_well_known` — pull the standard disclosure files (robots.txt,
  sitemap.xml, security.txt, humans.txt) and parse anything useful out of them.
* :func:`probe_paths` — a polite, bounded directory-existence check over a
  built-in wordlist (or a caller-supplied one).  This is *active* traffic, so
  the server gates it behind scope + the intrusive-tools setting.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from ..net.http import HttpClient, HttpResult

_WELL_KNOWN = {
    "robots.txt": "/robots.txt",
    "sitemap.xml": "/sitemap.xml",
    "security.txt": "/.well-known/security.txt",
    "security.txt (legacy)": "/security.txt",
    "humans.txt": "/humans.txt",
    "manifest": "/manifest.json",
}

# A compact, high-signal wordlist for a first-pass directory probe.
DEFAULT_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui", "openapi.json",
    ".git/config", ".git/HEAD", ".env", ".env.local", "config.php", "config.json",
    "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql", "phpinfo.php",
    "server-status", "server-info", ".well-known/security.txt", "robots.txt",
    "sitemap.xml", "actuator", "actuator/health", "actuator/env", "metrics",
    "debug", "test", "dev", "staging", "old", "tmp", "uploads", "files",
    "console", "cpanel", "webmail", "phpmyadmin", "adminer.php", "info.php",
    "readme.md", "readme.txt", "license.txt", "changelog.txt", "CHANGELOG.md",
    "wp-config.php.bak", "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
]

_ROBOTS_PATH_RE = re.compile(r"^\s*(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


@dataclass
class WellKnown:
    base_url: str
    files: dict[str, dict] = field(default_factory=dict)
    robots_paths: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)


@dataclass
class PathHit:
    path: str
    url: str
    status: int
    length: int
    content_type: str | None = None
    redirect_to: str | None = None


@dataclass
class ContentScan:
    base_url: str
    tested: int
    hits: list[PathHit] = field(default_factory=list)
    duration_ms: float = 0.0


def _base_url(host: str, scheme: str, port: int | None) -> str:
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


async def fetch_well_known(
    client: HttpClient, host: str, *, scheme: str = "https", port: int | None = None
) -> WellKnown:
    base = _base_url(host, scheme, port)
    wk = WellKnown(base_url=base)

    async def grab(label: str, path: str) -> None:
        r = await client.fetch(base + path, timeout=15.0, follow_redirects=True)
        if r.status and r.status == 200 and r.body:
            body = r.text(limit=100_000)
            wk.files[label] = {
                "url": r.final_url,
                "status": r.status,
                "content_type": r.header("Content-Type"),
                "length": len(r.body),
                "preview": body[:2000],
            }
            if "robots" in label:
                wk.robots_paths = sorted({m for m in _ROBOTS_PATH_RE.findall(body)})[:200]
            if "sitemap" in label:
                wk.sitemap_urls = sorted(set(_SITEMAP_LOC_RE.findall(body)))[:200]

    await asyncio.gather(*(grab(label, path) for label, path in _WELL_KNOWN.items()))
    return wk


async def probe_paths(
    client: HttpClient,
    host: str,
    *,
    scheme: str = "https",
    port: int | None = None,
    wordlist: list[str] | None = None,
    concurrency: int = 15,
    positive_statuses: tuple[int, ...] = (200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403, 405),
) -> ContentScan:
    base = _base_url(host, scheme, port)
    words = wordlist or DEFAULT_WORDLIST
    sem = asyncio.Semaphore(max(1, concurrency))
    loop = asyncio.get_event_loop()
    start = loop.time()

    async def check(path: str) -> PathHit | None:
        async with sem:
            url = f"{base}/{path.lstrip('/')}"
            r: HttpResult = await client.fetch(url, method="GET", timeout=10.0, follow_redirects=False, max_body=2048)
            if r.status in positive_statuses:
                return PathHit(
                    path=path,
                    url=url,
                    status=r.status,
                    length=len(r.body),
                    content_type=r.header("Content-Type"),
                    redirect_to=r.header("Location") if r.status and 300 <= r.status < 400 else None,
                )
            return None

    results = await asyncio.gather(*(check(w) for w in words))
    hits = sorted((h for h in results if h), key=lambda h: (h.status, h.path))
    return ContentScan(
        base_url=base,
        tested=len(words),
        hits=hits,
        duration_ms=round((loop.time() - start) * 1000, 1),
    )
