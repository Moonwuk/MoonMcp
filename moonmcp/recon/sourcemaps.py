"""Source-map recovery — turn a shipped `.js.map` back into original source.

A production bundle that ships (or leaves reachable) its `.js.map` embeds the
original, pre-minification source of every module in `sourcesContent[]`. Pulling
that back reconstructs the app's real source tree — internal routes, comments,
and hard-coded secrets that minification hid — and it is a common, high-impact
disclosure. `jsendpoints.analyze` already *detects* the map; this *recovers* it
and runs the recovered source through the existing secret scanner.

Detection-only: one or two in-scope GETs, JSON parsing, and offline secret
scanning. No traffic beyond fetching the map (+ the `.js` to locate it).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import urljoin

from ..net.http import HttpClient
from .jsendpoints import extract_source_maps
from .secrets import scan_text

# Recovered-file paths that don't come from the app itself.
_VENDOR_MARKERS = ("node_modules", "webpack://webpack/", "webpack/bootstrap",
                   "(webpack)", "/vendor/", "webpack://webpack-")
# Path fragments that make a recovered file worth reading first.
_INTERESTING = ("env", "config", "secret", "credential", "settings", ".key",
                ".pem", "auth", "token", "aws", "firebase", "apikey", "api-key")


def parse_source_map(raw: str) -> dict:
    """Parse a source map, tolerating the ``)]}'`` XSSI guard prefix some emit."""

    s = (raw or "").lstrip()
    if not s.startswith("{"):
        i = s.find("{")
        if i == -1:
            return {}
        s = s[i:]
    try:
        data = json.loads(s)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def is_vendor(path: str) -> bool:
    """A recovered path that belongs to a dependency, not the app's own source."""

    low = path.lower()
    return any(m in low for m in _VENDOR_MARKERS)


def recover_files(sm: dict, *, max_files: int = 300,
                  max_total_bytes: int = 8_000_000) -> tuple[list[dict], bool]:
    """Pair ``sources`` with ``sourcesContent``. Returns ``(files, truncated)``;
    each file = ``{path, content, recovered, vendor, interesting}``."""

    sources = sm.get("sources") or []
    contents = sm.get("sourcesContent") or []
    root = sm.get("sourceRoot") or ""
    out: list[dict] = []
    total = 0
    truncated = False
    for i, src in enumerate(sources):
        if not isinstance(src, str):
            continue
        path = root + src if root and not src.startswith(("http", "/")) else src
        content = contents[i] if i < len(contents) and isinstance(contents[i], str) else None
        vendor = is_vendor(path)
        low = path.lower()
        entry = {"path": path, "content": content or "", "recovered": content is not None,
                 "vendor": vendor, "interesting": any(k in low for k in _INTERESTING)}
        if content is not None:
            total += len(content)
            if len(out) >= max_files or total > max_total_bytes:
                truncated = True
                entry["content"] = ""
                entry["recovered"] = False
        out.append(entry)
    return out, truncated


# Real-world .js.map files are routinely multi-MB (1-20 MB). Fetch with an explicit
# large cap instead of inheriting the HttpClient's 512 KiB default, which truncated
# every real map mid-JSON so json.loads failed and the tool reported "not a source
# map" — a silent false negative on the exact disclosure it exists to find. Still
# bounded (a source map fetch is opt-in recon, not unbounded) so a hostile map can't
# exhaust memory.
_MAX_MAP_BYTES = 32 * 1024 * 1024  # 32 MiB


async def _fetch_map(client: HttpClient, url: str, scope_check) -> tuple[str | None, str | None, bool]:
    """Resolve *url* (a `.js`, a `.js.map`, or a page) to ``(map_url, raw, truncated)``."""

    r = await client.fetch(url, method="GET", follow_redirects=True, timeout=15.0,
                           max_body=_MAX_MAP_BYTES, scope_check=scope_check)
    if r.status is None or not r.body:
        return None, None, False
    body = r.text()
    if '"sources"' in body[:4000] or url.rstrip("/").endswith(".map"):
        return (r.final_url or url), body, r.truncated
    # a .js (or HTML) referencing a map — follow sourceMappingURL, else guess `<url>.map`
    maps = extract_source_maps(body)
    map_url = urljoin(r.final_url or url, maps[0]) if maps else (url.split("?", 1)[0] + ".map")
    if map_url.startswith("data:"):
        return None, None, False
    # sourceMappingURL is attacker-controllable (it comes from the remote JS body) and
    # can point cross-origin. fetch() only scope-checks REDIRECT hops, not the initial
    # one, so re-check the derived URL here or we would fetch out-of-scope and leak the
    # engagement auth headers to a third-party host.
    if scope_check is not None and not scope_check(map_url):
        return None, None, False
    m = await client.fetch(map_url, method="GET", follow_redirects=True, timeout=15.0,
                           max_body=_MAX_MAP_BYTES, scope_check=scope_check)
    if m.status is None or not m.body:
        return None, None, False
    return (m.final_url or map_url), m.text(), m.truncated


async def recover(client: HttpClient, url: str, *,
                  scope_check: Callable[[str], bool] | None = None) -> dict:
    """Fetch and parse the source map for *url*, recover its files, and scan the
    recovered app source for secrets."""

    map_url, raw, truncated_fetch = await _fetch_map(client, url, scope_check)
    if raw is None:
        return {"target": url, "recovered": False, "error": "no reachable source map"}
    sm = parse_source_map(raw)
    if not sm.get("sources"):
        if truncated_fetch:
            # An oversized map hit the fetch cap and was truncated before it could be
            # parsed — report that loudly rather than mislabelling it "not a source map".
            return {"target": url, "map_url": map_url, "recovered": False, "truncated": True,
                    "error": f"source map exceeded the {_MAX_MAP_BYTES // (1024 * 1024)} MiB fetch "
                             "cap and was truncated before parsing — fetch it directly"}
        return {"target": url, "map_url": map_url, "recovered": False,
                "error": "response is not a valid source map (no sources[])"}

    files, truncated = recover_files(sm)
    app_files = [f for f in files if f["recovered"] and not f["vendor"]]
    secrets: list[dict] = []
    for f in app_files:
        for h in scan_text(f["content"], source=f["path"]):
            secrets.append({"file": f["path"], "type": h.type, "fp_risk": h.fp_risk,
                            "redacted": h.redacted, "context": h.context})

    return {
        "target": url, "map_url": map_url, "recovered": True, "truncated": truncated,
        "total_sources": len(files),
        "app_source_count": len(app_files),
        "app_sources": [f["path"] for f in app_files][:200],
        "interesting_files": [f["path"] for f in app_files if f["interesting"]][:50],
        "secret_count": len(secrets),
        "secrets": secrets[:100],
        "note": (f"recovered {len(app_files)} app source file(s)"
                 + (f", {len(secrets)} secret(s) — rotate them" if secrets else "")
                 + " — original source disclosed via the shipped .js.map"),
    }
