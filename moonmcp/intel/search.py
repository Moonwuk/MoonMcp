"""Internet search — keyless web search + a Google-dork generator.

`web_search` queries a keyless engine (DuckDuckGo's HTML endpoint) through the
shared HTTP client and returns structured results (title, url, snippet) — passive
OSINT that never touches the target.  `generate_dorks` builds categorised
search-engine dork queries for a target domain (exposed files, login panels,
config/secrets, directory listings, code leaks, …) — pure and offline.
"""

from __future__ import annotations

import html
import re
import urllib.parse

_DDG_HTML = "https://html.duckduckgo.com/html/?q="
_RESULT_A = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                       re.IGNORECASE | re.DOTALL)
_SNIPPET = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
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


async def web_search(http_client, query: str, max_results: int = 10) -> dict:
    """Search the web (keyless, via DuckDuckGo HTML) and return structured results."""

    q = query.strip()
    if not q:
        return {"query": query, "results": [], "error": "empty query"}
    url = _DDG_HTML + urllib.parse.quote(q)
    try:
        r = await http_client.fetch(
            url, method="GET", follow_redirects=True,
            headers={"Accept-Language": "en-US,en;q=0.9"},
        )
    except Exception as exc:
        return {"query": q, "results": [], "error": f"{type(exc).__name__}: {exc}"}
    if r.status is None:
        return {"query": q, "results": [],
                "error": r.error or "search request failed (outbound network blocked?)"}
    results = parse_ddg_html(r.text(), max_results=max_results)
    return {"query": q, "engine": "duckduckgo", "count": len(results), "results": results}


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
