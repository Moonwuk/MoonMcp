"""Web page reader — turn an arbitrary OSINT URL into clean, readable text.

`web_read` fetches any **public** web page through the shared HTTP client and
returns its title, meta description, main readable text and outbound links, so an
agent researching a target (vendor docs, a CVE writeup, a security blog, a
company's about-page) gets the *content* instead of a raw HTML blob or a bare
search snippet. It complements `web_search`: search finds the page, `web_read`
reads it.

Security posture (this tool is deliberately **not** target-scoped, like
`web_search` — it reads third-party OSINT, not the engagement target):

* The shared client's **connect-guard (block-private SSRF)** still applies on
  every hop, so a URL — or a redirect — pointing at a private/reserved/link-local
  IP (cloud metadata, an internal host) is refused. This is the SSRF choke point.
* **`suppress_auth=True`** — engagement credentials are never attached to a
  random third-party page.

Parsing is pure stdlib (`html.parser`): `<script>`/`<style>`/`<template>`/`<svg>`
and comments are dropped, block elements become line breaks, entities are
unescaped, and whitespace is collapsed — no external dependency.
"""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# Elements whose text content is never human-readable page text. (Not "head" —
# the <title> lives there and we want its text.)
_SKIP_CONTENT = {"script", "style", "noscript", "template", "svg"}
# Block-level elements that should force a line break around their text.
_BLOCK = {
    "p", "div", "section", "article", "header", "footer", "nav", "aside", "main",
    "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "table", "tr", "td",
    "th", "blockquote", "pre", "figure", "figcaption", "br", "hr", "form",
}
_WS = re.compile(r"[ \t\f\v]+")
_BLANKS = re.compile(r"\n\s*\n\s*\n+")


class _Reader(HTMLParser):
    """Collect title, meta description, readable text and links from HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self.description = ""
        self._parts: list[str] = []
        self._links: list[dict] = []
        self._seen_links: set[str] = set()
        self._skip_depth = 0
        self._in_title = False
        self._link_text: list[str] = []
        self._in_link = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_CONTENT:
            self._skip_depth += 1
            return
        amap = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = (amap.get("name") or amap.get("property") or "").lower()
            if name in ("description", "og:description") and not self.description:
                self.description = html.unescape(amap.get("content", "")).strip()
        elif tag == "a":
            href = amap.get("href", "").strip()
            if href and not href.startswith(("javascript:", "#", "mailto:", "data:")):
                try:
                    absolute = urljoin(self.base_url, href)
                except ValueError:
                    absolute = href
                if absolute.startswith(("http://", "https://")):
                    self._in_link = True
                    self._link_text = []
                    self._pending_href = absolute
        elif tag in _BLOCK:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_CONTENT:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "title":
            self._in_title = False
        elif tag == "a" and self._in_link:
            self._in_link = False
            href = getattr(self, "_pending_href", "")
            if href and href not in self._seen_links:
                self._seen_links.add(href)
                text = _WS.sub(" ", " ".join(self._link_text)).strip()
                self._links.append({"url": href, "text": text[:120]})
        elif tag in _BLOCK:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data
            return
        text = _WS.sub(" ", data)
        if text.strip() or text == " ":
            self._parts.append(text)
        if self._in_link:
            self._link_text.append(data)

    def readable_text(self) -> str:
        joined = "".join(self._parts)
        # Collapse runs of blank lines and trim each line.
        lines = [ln.strip() for ln in joined.split("\n")]
        collapsed = "\n".join(ln for ln in lines if ln)
        return _BLANKS.sub("\n\n", collapsed).strip()

    def links(self) -> list[dict]:
        return self._links


def extract_readable(body: str, base_url: str, *, max_chars: int = 20000,
                     max_links: int = 100) -> dict:
    """Parse HTML into ``{title, description, text, links, word_count, truncated}``
    (pure — no I/O). Text is capped at ``max_chars`` and links at ``max_links``."""

    parser = _Reader(base_url)
    try:
        parser.feed(body or "")
        parser.close()
    except Exception:  # noqa: BLE001 - a malformed page must never crash the reader
        pass
    text = parser.readable_text()
    truncated = len(text) > max_chars
    if truncated:
        text = text[:max_chars]
    return {
        "title": html.unescape(_WS.sub(" ", parser.title).strip()),
        "description": parser.description,
        "text": text,
        "links": parser.links()[:max_links],
        "word_count": len(text.split()),
        "truncated": truncated,
    }


def _looks_html(content_type: str, body: str) -> bool:
    ct = (content_type or "").lower()
    if "html" in ct or "xml" in ct:
        return True
    if ct.startswith(("application/json", "text/plain", "text/csv")):
        return False
    head = body[:512].lstrip().lower()
    return head.startswith(("<!doctype", "<html", "<head", "<body")) or "<title" in head


async def web_read(http_client, url: str, *, max_chars: int = 20000) -> dict:
    """Fetch a public OSINT page and return its readable content.

    Not target-scoped by design (reads third-party research pages); the client's
    block-private SSRF guard still refuses private/internal hosts and redirects,
    and engagement auth is suppressed."""

    raw = (url or "").strip()
    if not raw:
        return {"url": url, "error": "empty url"}
    if "://" not in raw:
        raw = "https://" + raw
    scheme = urlsplit(raw).scheme.lower()
    if scheme not in ("http", "https"):
        return {"url": url, "error": f"unsupported scheme '{scheme}' (http/https only)"}
    try:
        r = await http_client.fetch(
            raw, method="GET", follow_redirects=True, suppress_auth=True,
            headers={"Accept-Language": "en-US,en;q=0.9",
                     "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8"},
        )
    except Exception as exc:  # noqa: BLE001 - surface any transport failure as JSON
        return {"url": raw, "error": f"{type(exc).__name__}: {exc}"}
    if r.blocked_reason:
        return {"url": raw, "error": f"blocked: {r.blocked_reason}"}
    if r.status is None:
        return {"url": raw, "error": r.error or "request failed (outbound network blocked?)"}
    body = r.text()
    content_type = r.header("content-type", "") or ""
    base = {"url": raw, "final_url": r.final_url, "status": r.status,
            "content_type": content_type.split(";")[0].strip() or None}
    if r.redirect_blocked:
        base["redirect_blocked"] = r.redirect_blocked
    if _looks_html(content_type, body):
        base.update(extract_readable(body, r.final_url or raw, max_chars=max_chars))
    else:
        # Non-HTML (JSON/plain/CSV): return the raw text, capped.
        truncated = len(body) > max_chars
        base.update({"title": "", "description": "",
                     "text": body[:max_chars] if truncated else body,
                     "links": [], "word_count": len(body.split()), "truncated": truncated})
    return base
