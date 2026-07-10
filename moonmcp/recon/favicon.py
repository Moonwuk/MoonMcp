"""Favicon hashing for asset pivoting.

Computes the Shodan-style favicon hash (``mmh3`` MurmurHash3 x86_32, signed, over
the standard-base64 encoding of the icon).  Two hosts sharing a favicon hash are
very often the same product/instance, so the hash is a powerful pivot: search
``http.favicon.hash:<hash>`` on Shodan/Censys/FOFA to find sibling assets — a
classic way to discover origin servers hiding behind a CDN/WAF.

MurmurHash3 is reimplemented in pure Python so no ``mmh3`` dependency is needed.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from urllib.parse import urljoin

from ..net.http import HttpClient

_ICON_LINK_RE = re.compile(
    r"""<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*>""", re.IGNORECASE)
_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32, returned as a **signed** 32-bit int (Shodan's convention)."""

    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & 0xFFFFFFFC
    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xFF) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1] & 0xFF) << 8
    if tail >= 1:
        k1 |= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(icon_bytes: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3 of the base64 (with newlines) of the icon."""

    b64 = base64.encodebytes(icon_bytes)  # standard base64, 76-col wrapped with \n
    return murmur3_32(b64)


@dataclass
class FaviconResult:
    url: str
    favicon_url: str | None = None
    hash: int | None = None
    size_bytes: int = 0
    content_type: str | None = None
    shodan_query: str | None = None
    censys_query: str | None = None
    error: str | None = None


async def fetch_favicon_hash(client: HttpClient, base_url: str, *, scope_check=None) -> FaviconResult:
    result = FaviconResult(url=base_url)

    # Prefer the <link rel="icon"> href if the page declares one.
    favicon_url = urljoin(base_url, "/favicon.ico")
    page = await client.fetch(base_url, follow_redirects=True, timeout=12.0, scope_check=scope_check)
    if page.status is not None and page.body:
        m = _ICON_LINK_RE.search(page.text(limit=100_000))
        if m:
            href = _HREF_RE.search(m.group(0))
            if href:
                favicon_url = urljoin(page.final_url or base_url, href.group(1))

    # The <link rel="icon"> href can be an ABSOLUTE URL to any host — refuse to
    # fetch (with engagement auth attached) a favicon that left the scope.
    if scope_check is not None and not scope_check(favicon_url):
        result.error = "favicon URL is out of scope"
        return result

    r = await client.fetch(favicon_url, follow_redirects=True, timeout=12.0,
                           max_body=512 * 1024, scope_check=scope_check)
    if r.status != 200 or not r.body:
        result.error = f"no favicon (HTTP {r.status})" if r.status is not None else (r.error or "unreachable")
        return result

    result.favicon_url = r.final_url or favicon_url
    result.size_bytes = len(r.body)
    result.content_type = r.header("Content-Type")
    result.hash = favicon_hash(r.body)
    result.shodan_query = f"http.favicon.hash:{result.hash}"
    result.censys_query = "services.http.response.favicons.md5_hash: <md5 of same icon>"
    return result
