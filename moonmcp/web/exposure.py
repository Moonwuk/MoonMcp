"""Exposed VCS / config file detection.

Confirms a genuinely exposed ``.git`` (or ``.svn``/``.env``) rather than just a
200 status: it validates the content signature (``.git/HEAD`` starts with
``ref:``, ``.git/config`` has a ``[core]`` stanza, ...) to avoid the soft-404
false positives that plague naive path probing.  Source-code disclosure via an
exposed ``.git`` is a high-impact, common bug-bounty finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ..net.http import HttpClient

# path -> (signature substring the real file must contain, human label)
_CHECKS: dict[str, tuple[str, str]] = {
    "/.git/HEAD": ("ref:", "Git HEAD"),
    "/.git/config": ("[core]", "Git config"),
    "/.git/logs/HEAD": ("", "Git commit log"),
    "/.svn/entries": ("", "SVN entries"),
    "/.svn/wc.db": ("SQLite format 3", "SVN wc.db"),
    "/.hg/requires": ("", "Mercurial requires"),
    "/.env": ("=", "Env file"),
    "/.DS_Store": ("Bud1", "macOS .DS_Store"),
    "/.git/index": ("DIRC", "Git index"),
}

_REMOTE_URL_RE = re.compile(r"url\s*=\s*(\S+)")


@dataclass
class ExposedFile:
    path: str
    label: str
    status: int
    size: int
    confirmed: bool
    detail: str = ""


@dataclass
class ExposureResult:
    base_url: str
    git_exposed: bool = False
    exposed: list[ExposedFile] = field(default_factory=list)
    git_remote: str | None = None
    recent_commits: list[str] = field(default_factory=list)


def _looks_like_html(text: str) -> bool:
    head = text.lstrip()[:200].lower()
    return head.startswith("<!doctype html") or "<html" in head


async def check_exposure(client: HttpClient, base_url: str, *, scope_check=None) -> ExposureResult:
    result = ExposureResult(base_url=base_url)
    for path, (signature, label) in _CHECKS.items():
        url = urljoin(base_url, path)
        r = await client.fetch(url, follow_redirects=False, timeout=10.0, scope_check=scope_check)
        if r.status != 200 or not r.body:
            continue
        text = r.text(limit=8000)
        # A soft-404 that returns 200 with an HTML page is not a real exposure. This
        # applies to the EMPTY-signature entries too (/.git/logs/HEAD, /.svn/entries,
        # /.hg/requires) — a real commit log / entries file is plain text, never an
        # HTML document, so an HTML body there is a soft-404, not an exposed VCS file.
        # (Previously empty signatures skipped this guard and were always confirmed.)
        if _looks_like_html(text) and signature != "<":
            confirmed = False
        else:
            confirmed = (signature == "") or (signature in text) or (signature.encode() in r.body[:64])
        entry = ExposedFile(path=path, label=label, status=r.status, size=len(r.body), confirmed=confirmed)
        if confirmed and path == "/.git/config":
            m = _REMOTE_URL_RE.search(text)
            if m:
                result.git_remote = m.group(1)
                entry.detail = f"remote: {m.group(1)}"
        if confirmed and path == "/.git/logs/HEAD":
            for line in text.splitlines()[:10]:
                parts = line.split()
                if len(parts) >= 2:
                    result.recent_commits.append(" ".join(parts[:2]))
        if confirmed and path.startswith("/.git"):
            result.git_exposed = True
        result.exposed.append(entry)
    return result
