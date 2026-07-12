"""Internet search — keyless web search + a Google-dork generator.

`web_search` queries **keyless** engines through the shared HTTP client and
returns structured results (title, url, snippet) — passive OSINT that never
touches the target. It's **resilient by design**: it tries several engines
(DuckDuckGo HTML → DuckDuckGo Lite → Bing) in order and returns the first that
answers, so a single engine rate-limiting or changing its markup doesn't blind
the agent. Results are de-duplicated by URL and an optional ``site`` filter
scopes the query to one domain. `generate_dorks` builds categorised
search-engine dork queries for a target domain (exposed files, login panels,
config/secrets, directory listings, code leaks, …) — pure and offline.
"""

from __future__ import annotations

import html
import re
import urllib.parse

_DDG_HTML = "https://html.duckduckgo.com/html/?q="
_DDG_LITE = "https://lite.duckduckgo.com/lite/?q="
_BING = "https://www.bing.com/search?q="
_RESULT_A = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                       re.IGNORECASE | re.DOTALL)
_SNIPPET = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
# DDG Lite puts href BEFORE class, so match the whole <a …> tag (attrs order-agnostic)
# and pull the href out of the captured attribute string.
_LITE_A = re.compile(r'<a\b([^>]*\bclass=["\']result-link["\'][^>]*)>(.*?)</a>',
                     re.IGNORECASE | re.DOTALL)
_LITE_HREF = re.compile(r'href="([^"]+)"', re.IGNORECASE)
_LITE_SNIP = re.compile(r'class=["\']result-snippet["\'][^>]*>(.*?)</td>',
                        re.IGNORECASE | re.DOTALL)
_BING_LI = re.compile(r'<li class="b_algo".*?</li>', re.IGNORECASE | re.DOTALL)
_BING_A = re.compile(r'<h2>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_BING_P = re.compile(r"<p[^>]*>(.*?)</p>", re.IGNORECASE | re.DOTALL)
_TAG = re.compile(r"<[^>]+>")


def _clean(text: str) -> str:
    return html.unescape(_TAG.sub("", text)).strip()


def _real_url(href: str) -> str:
    """DuckDuckGo wraps result links as //duckduckgo.com/l/?uddg=<encoded>."""

    if "uddg=" in href:
        try:
            q = urllib.parse.urlparse(href if "//" not in href[:2] else "https:" + href).query
            uddg = urllib.parse.parse_qs(q).get("uddg", [])
            if uddg:
                return urllib.parse.unquote(uddg[0])
        except Exception:
            pass
    if href.startswith("//"):
        return "https:" + href
    return href


def parse_ddg_html(body: str, max_results: int = 10) -> list[dict]:
    """Parse DuckDuckGo HTML results into ``[{title, url, snippet}]`` (pure)."""

    titles = _RESULT_A.findall(body or "")
    snippets = [_clean(s) for s in _SNIPPET.findall(body or "")]
    out: list[dict] = []
    for i, (href, title) in enumerate(titles[:max_results]):
        out.append({
            "title": _clean(title),
            "url": _real_url(html.unescape(href)),
            "snippet": snippets[i] if i < len(snippets) else "",
        })
    return out


def parse_ddg_lite(body: str, max_results: int = 10) -> list[dict]:
    """Parse DuckDuckGo Lite results into ``[{title, url, snippet}]`` (pure)."""

    links = _LITE_A.findall(body or "")
    snippets = [_clean(s) for s in _LITE_SNIP.findall(body or "")]
    out: list[dict] = []
    for i, (attrs, title) in enumerate(links[:max_results]):
        href_m = _LITE_HREF.search(attrs)
        if not href_m:
            continue
        out.append({
            "title": _clean(title),
            "url": _real_url(html.unescape(href_m.group(1))),
            "snippet": snippets[i] if i < len(snippets) else "",
        })
    return out


def parse_bing(body: str, max_results: int = 10) -> list[dict]:
    """Parse Bing search results into ``[{title, url, snippet}]`` (pure)."""

    out: list[dict] = []
    for block in _BING_LI.findall(body or "")[:max_results * 2]:
        m = _BING_A.search(block)
        if not m:
            continue
        href = html.unescape(m.group(1).strip())
        if not href.startswith(("http://", "https://")):
            continue
        snip = _BING_P.search(block)
        out.append({
            "title": _clean(m.group(2)),
            "url": href,
            "snippet": _clean(snip.group(1)) if snip else "",
        })
        if len(out) >= max_results:
            break
    return out


# Engine registry: (name, url_prefix, parser). Tried in order until one answers.
_ENGINES = (
    ("duckduckgo", _DDG_HTML, parse_ddg_html),
    ("duckduckgo-lite", _DDG_LITE, parse_ddg_lite),
    ("bing", _BING, parse_bing),
)


def _dedup(results: list[dict]) -> list[dict]:
    """Drop duplicate URLs (order-preserving), ignoring a trailing slash."""

    seen: set[str] = set()
    out: list[dict] = []
    for item in results:
        key = (item.get("url") or "").rstrip("/").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


async def web_search(http_client, query: str, max_results: int = 10,
                     site: str | None = None) -> dict:
    """Search the web (keyless) with **multi-engine fallback**.

    Tries DuckDuckGo HTML → DuckDuckGo Lite → Bing, returning the first engine
    that yields results (so one engine failing/rate-limiting doesn't blind the
    search). ``site`` scopes the query to a single domain. Degrades gracefully to
    an empty result set (never raises) when outbound network is blocked."""

    q = query.strip()
    if site and site.strip():
        dom = site.strip().lstrip("*.").lower()
        if f"site:{dom}" not in q:
            q = f"site:{dom} {q}".strip()
    if not q:
        return {"query": query, "results": [], "error": "empty query"}
    encoded = urllib.parse.quote(q)
    errors: list[str] = []
    for name, prefix, parser in _ENGINES:
        try:
            r = await http_client.fetch(
                prefix + encoded, method="GET", follow_redirects=True, suppress_auth=True,
                headers={"Accept-Language": "en-US,en;q=0.9",
                         "User-Agent": "Mozilla/5.0 (compatible; MoonMCP-OSINT/1.0)"},
            )
        except Exception as exc:  # noqa: BLE001 - try the next engine
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if r.status is None:
            errors.append(f"{name}: {r.error or 'no response'}")
            continue
        results = _dedup(parser(r.text(), max_results=max_results))
        if results:
            return {"query": q, "engine": name, "count": len(results),
                    "results": results[:max_results]}
        errors.append(f"{name}: no results (status {r.status})")
    return {"query": q, "results": [], "engines_tried": [e[0] for e in _ENGINES],
            "error": "; ".join(errors) or "no engine returned results"}


# --- Google/Bing dork generator ---------------------------------------------
def _dork_catalog(domain: str) -> dict[str, list[str]]:
    d = domain.strip().lstrip("*.").lower()
    site = f"site:{d}"
    return {
        "subdomains": [f"site:*.{d} -site:www.{d}", f"site:{d} -site:www.{d}"],
        "files": [
            f"{site} (ext:sql OR ext:bak OR ext:old OR ext:backup OR ext:swp)",
            f"{site} (ext:env OR ext:ini OR ext:conf OR ext:cnf OR ext:config)",
            f"{site} (ext:log OR ext:txt OR ext:xml OR ext:json)",
            f"{site} (filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx)",
        ],
        "config_secrets": [
            f'{site} (intext:"api_key" OR intext:"apikey" OR intext:"client_secret" OR intext:"access_token")',
            f'{site} (intext:"BEGIN RSA PRIVATE KEY" OR intext:"aws_secret_access_key")',
            f"{site} (inurl:config OR inurl:.env OR inurl:settings OR inurl:credentials)",
        ],
        "login_admin": [
            f"{site} (inurl:login OR inurl:signin OR inurl:admin OR inurl:dashboard)",
            f'{site} (intitle:"login" OR intitle:"admin" OR intitle:"sign in")',
            f"{site} (inurl:wp-admin OR inurl:phpmyadmin OR inurl:cpanel OR inurl:webmail)",
        ],
        "directory_listing": [f'{site} intitle:"index of" (inurl:backup OR inurl:admin OR inurl:uploads)'],
        "errors_debug": [
            f'{site} (intext:"sql syntax near" OR intext:"Warning: mysql" OR intext:"ORA-" OR intext:"stack trace")',
            f'{site} (intext:"Fatal error" OR intext:"Uncaught exception" OR intext:"DEBUG")',
        ],
        "code_leaks": [
            f'"{d}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)',
            f'"{d}" (site:pastebin.com OR site:trello.com OR site:s3.amazonaws.com)',
            f'"{d}" (inurl:"/.git" OR intext:"password" site:github.com)',
        ],
        "exposed_services": [
            f"{site} (inurl:jenkins OR inurl:grafana OR inurl:kibana OR inurl:swagger OR inurl:api-docs)",
            f'{site} (intitle:"phpinfo()" OR inurl:phpinfo)',
        ],
        "open_redirect_ssrf": [
            f"{site} (inurl:redirect OR inurl:url= OR inurl:next= OR inurl:return OR inurl:dest=)",
        ],
    }


def generate_dorks(domain: str, category: str | None = None) -> dict:
    """Build categorised Google/Bing dork queries for *domain* (offline)."""

    catalog = _dork_catalog(domain)
    if category:
        c = category.strip().lower()
        if c not in catalog:
            return {"domain": domain, "error": f"unknown category '{category}'",
                    "categories": sorted(catalog)}
        return {"domain": domain, "category": c, "dorks": catalog[c]}
    total = sum(len(v) for v in catalog.values())
    return {"domain": domain, "count": total, "categories": sorted(catalog), "dorks": catalog}
