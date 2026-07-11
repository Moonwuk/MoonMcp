"""Lightweight technology fingerprinting from HTTP responses.

A curated signature set matches on response headers, cookies, and common HTML
body markers.  This is intentionally dependency-free (no Wappalyzer database) but
covers the technologies that matter most for a first-pass recon: servers, CDNs,
frameworks, CMSs, and language runtimes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..net.http import HttpResult


@dataclass
class Technology:
    name: str
    category: str
    evidence: str
    version: str | None = None


@dataclass
class Fingerprint:
    url: str
    status: int | None
    title: str | None = None
    server: str | None = None
    powered_by: str | None = None
    technologies: list[Technology] = field(default_factory=list)
    ip: str | None = None


# (name, category, where, pattern) — where ∈ {header:<name>, cookie, body}
_SIGNATURES: list[tuple[str, str, str, str]] = [
    # Servers
    ("nginx", "web-server", "header:server", r"nginx(?:/([\d.]+))?"),
    ("Apache", "web-server", "header:server", r"apache(?:/([\d.]+))?"),
    ("Microsoft IIS", "web-server", "header:server", r"iis(?:/([\d.]+))?"),
    ("LiteSpeed", "web-server", "header:server", r"litespeed"),
    ("Caddy", "web-server", "header:server", r"caddy"),
    ("OpenResty", "web-server", "header:server", r"openresty(?:/([\d.]+))?"),
    # CDNs / WAFs
    ("Cloudflare", "cdn", "header:server", r"cloudflare"),
    ("Cloudflare", "cdn", "header:cf-ray", r".+"),
    ("Akamai", "cdn", "header:x-akamai-transformed", r".+"),
    ("Fastly", "cdn", "header:x-served-by", r"cache-.*"),
    ("Amazon CloudFront", "cdn", "header:x-amz-cf-id", r".+"),
    ("Sucuri", "waf", "header:x-sucuri-id", r".+"),
    ("Imperva/Incapsula", "waf", "header:x-iinfo", r".+"),
    # Languages / runtimes
    ("PHP", "language", "header:x-powered-by", r"php(?:/([\d.]+))?"),
    ("PHP", "language", "cookie", r"phpsessid"),
    ("ASP.NET", "framework", "header:x-powered-by", r"asp\.net"),
    ("ASP.NET", "framework", "header:x-aspnet-version", r"([\d.]+)"),
    ("ASP.NET", "framework", "cookie", r"asp\.net_sessionid"),
    ("Express", "framework", "header:x-powered-by", r"express"),
    ("Node.js", "language", "header:x-powered-by", r"node"),
    ("Java", "language", "cookie", r"jsessionid"),
    ("Ruby on Rails", "framework", "cookie", r"_rails|_session_id"),
    ("Django", "framework", "cookie", r"csrftoken|django"),
    ("Laravel", "framework", "cookie", r"laravel_session"),
    ("Flask", "framework", "cookie", r"session=eyj"),
    # CMS
    ("WordPress", "cms", "body", r"wp-content|wp-includes|/wp-json"),
    ("WordPress", "cms", "header:link", r"wp\.me|/wp-json"),
    ("Drupal", "cms", "header:x-generator", r"drupal(?:\s*([\d.]+))?"),
    ("Drupal", "cms", "body", r'name="Generator"\s+content="Drupal'),
    ("Joomla", "cms", "body", r"/media/jui/|joomla"),
    ("Ghost", "cms", "body", r'content="Ghost'),
    ("Shopify", "ecommerce", "header:x-shopify-stage", r".+"),
    ("Magento", "ecommerce", "cookie", r"frontend=|mage-"),
    # Front-end
    ("React", "js-framework", "body",
     r"__reactcontainer|react-root|data-reactroot|data-reactid|react-dom|react\.(?:production|development)"),
    ("Vue.js", "js-framework", "body", r"data-v-[0-9a-f]{8}|__vue__"),
    ("Angular", "js-framework", "body", r"ng-version|ng-app|angular"),
    ("Next.js", "js-framework", "body", r"/_next/|__next_data__"),
    ("Nuxt.js", "js-framework", "body", r"__nuxt__|/_nuxt/"),
    # Infra / dev
    ("Gunicorn", "web-server", "header:server", r"gunicorn(?:/([\d.]+))?"),
    ("Werkzeug", "web-server", "header:server", r"werkzeug(?:/([\d.]+))?"),
    ("Kestrel", "web-server", "header:server", r"kestrel"),
    ("Varnish", "cache", "header:via", r"varnish"),
    ("Vercel", "hosting", "header:server", r"vercel"),
    ("Netlify", "hosting", "header:server", r"netlify"),
    ("GitHub Pages", "hosting", "header:server", r"github\.com"),
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(body: str) -> str | None:
    m = _TITLE_RE.search(body)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:200] or None


def fingerprint(result: HttpResult, ip: str | None = None) -> Fingerprint:
    body = result.text(limit=200_000)
    headers_lc = {k.lower(): v for k, v in result.headers}
    cookies = " ".join(result.get_all("set-cookie")).lower()

    fp = Fingerprint(
        url=result.final_url or result.url,
        status=result.status,
        title=_extract_title(body),
        server=headers_lc.get("server"),
        powered_by=headers_lc.get("x-powered-by"),
        ip=ip,
    )

    by_name: dict[str, Technology] = {}
    for name, category, where, pattern in _SIGNATURES:
        haystack = ""
        label = where
        if where.startswith("header:"):
            haystack = headers_lc.get(where.split(":", 1)[1], "")
        elif where == "cookie":
            haystack = cookies
        elif where == "body":
            haystack = body
        if not haystack:
            continue
        m = re.search(pattern, haystack, re.IGNORECASE)
        if not m:
            continue
        version = None
        if m.groups():
            version = next((g for g in m.groups() if g), None)
        tech = Technology(name=name, category=category, evidence=label, version=version)
        existing = by_name.get(name)
        if existing is None:
            by_name[name] = tech
        elif version and not existing.version:
            # Upgrade a version-less match with a more specific, versioned one.
            by_name[name] = tech
    fp.technologies = list(by_name.values())
    return fp
