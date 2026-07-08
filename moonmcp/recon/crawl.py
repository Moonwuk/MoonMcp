"""A light, bounded, scope-safe web crawler.

Fetches a page (and optionally a handful of same-scope pages at depth 1) and
extracts the things a bug-bounty hunter wants first: links, forms and their
inputs, JavaScript/asset URLs, query parameters, and any external hosts the
page reaches out to.  Everything is HTML/regex parsing on the standard library —
no headless browser required.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlsplit

from ..net.http import HttpClient

_HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)["']""", re.IGNORECASE)
_JS_URL_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-./]+?\.(?:json|js|php|aspx?|jsp|do|action|api)[^"']*)["']""")
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_FORM_ATTR_RE = re.compile(r"""(action|method)\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT_RE = re.compile(r"""<(?:input|textarea|select)\b[^>]*?name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


@dataclass
class Form:
    action: str
    method: str
    inputs: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    base_url: str
    pages_crawled: list[str] = field(default_factory=list)
    internal_links: list[str] = field(default_factory=list)
    external_hosts: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)


_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def _extract(base: str, html: str) -> tuple[set[str], set[str], list[Form], set[str]]:
    links, js, params = set(), set(), set()
    for m in _HREF_RE.finditer(html):
        raw = m.group(1).strip()
        if raw.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
            continue
        absu = urljoin(base, raw)
        if not absu.startswith(("http://", "https://")):
            continue
        links.add(absu)
        q = urlsplit(absu).query
        for pair in q.split("&"):
            if "=" in pair:
                params.add(pair.split("=", 1)[0])
        if re.search(r"\.(?:js|json)(?:$|\?)", urlsplit(absu).path, re.IGNORECASE):
            js.add(absu)
    for jm in _JS_URL_RE.finditer(html):
        js.add(urljoin(base, jm.group(1)))
    forms: list[Form] = []
    for fm in _FORM_RE.finditer(html):
        block = fm.group(0)
        attrs = {k.lower(): v for k, v in _FORM_ATTR_RE.findall(block)}
        action = urljoin(base, attrs.get("action", "")) if attrs.get("action") else base
        forms.append(Form(action=action, method=(attrs.get("method") or "GET").upper(),
                          inputs=sorted(set(_INPUT_RE.findall(block)))))
    emails = set(_EMAIL_RE.findall(html))
    return links, js, forms, emails


async def crawl(
    client: HttpClient,
    base_url: str,
    *,
    scope_check: Callable[[str], bool] | None = None,
    max_pages: int = 10,
    depth: int = 1,
) -> CrawlResult:
    base_host = urlparse(base_url).hostname or ""
    result = CrawlResult(base_url=base_url)
    seen_pages: set[str] = set()
    internal: set[str] = set()
    external_hosts: set[str] = set()
    js_all: set[str] = set()
    params_all: set[str] = set()
    emails_all: set[str] = set()

    queue: list[tuple[str, int]] = [(base_url, 0)]
    while queue and len(seen_pages) < max_pages:
        url, d = queue.pop(0)
        if url in seen_pages:
            continue
        if scope_check is not None and not scope_check(url):
            continue
        seen_pages.add(url)
        r = await client.fetch(url, timeout=12.0, follow_redirects=True, scope_check=scope_check)
        ctype = (r.header("Content-Type") or "").lower()
        if r.status is None or (ctype and "html" not in ctype and "xml" not in ctype):
            continue
        links, js, forms, emails = _extract(r.final_url or url, r.text(limit=500_000))
        js_all |= js
        emails_all |= emails
        for f in forms:
            result.forms.append(f)
            params_all.update(f.inputs)
        for lk in links:
            h = urlparse(lk).hostname or ""
            if h == base_host:
                internal.add(lk)
                if "=" in urlsplit(lk).query:
                    for pair in urlsplit(lk).query.split("&"):
                        if "=" in pair:
                            params_all.add(pair.split("=", 1)[0])
                if d < depth and lk not in seen_pages:
                    queue.append((lk, d + 1))
            elif h:
                external_hosts.add(h)

    result.pages_crawled = sorted(seen_pages)
    result.internal_links = sorted(internal)[:500]
    result.external_hosts = sorted(external_hosts)
    result.js_files = sorted(js_all)[:200]
    result.parameters = sorted(params_all)
    result.emails = sorted(emails_all)[:100]
    return result
