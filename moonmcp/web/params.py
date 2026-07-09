"""Active hidden-parameter discovery.

Brute a wordlist of parameter names against a URL and flag the ones the app
actually *reacts* to — either by reflecting the probe value (a candidate
injection entry point: XSS/SSRF/SQLi) or by changing the response (status or a
meaningful length delta), which means the parameter is recognised.  Benign
canary values only; no payloads.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlencode

# A compact, high-signal default wordlist of common parameter names.
DEFAULT_PARAMS = [
    "id", "user", "username", "user_id", "uid", "account", "page", "p", "q", "query",
    "search", "s", "url", "uri", "redirect", "redirect_url", "next", "return", "returnUrl",
    "dest", "destination", "continue", "file", "filename", "path", "dir", "folder",
    "document", "template", "include", "load", "view", "action", "do", "cmd", "exec",
    "func", "callback", "jsonp", "debug", "test", "admin", "token", "auth", "key",
    "api_key", "apikey", "access_token", "sig", "signature", "hash", "lang", "locale",
    "format", "type", "mode", "sort", "order", "limit", "offset", "count", "ref",
    "source", "data", "json", "xml", "email", "name", "category", "tag", "filter",
    "year", "month", "day", "code", "state", "status", "value", "content",
]

_LEN_THRESHOLD = 24  # bytes; ignore tiny dynamic-content jitter


async def discover_parameters(
    http_client,
    url: str,
    *,
    wordlist: list[str] | None = None,
    method: str = "GET",
    canary: str = "moonfuzz9x7q",
    max_params: int = 80,
    scope_check=None,
) -> dict:
    """Probe *url* for hidden parameters. Returns the params the app reacts to."""

    m = method.strip().upper()
    words = wordlist or DEFAULT_PARAMS
    words = list(dict.fromkeys(w.strip() for w in words if w and w.strip()))[:max_params]

    base = await http_client.fetch(url, method=m, follow_redirects=False, scope_check=scope_check)
    base_len = len(base.body)
    base_status = base.status

    async def _probe(word: str) -> dict | None:
        if m == "GET":
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}{urlencode({word: canary})}"
            r = await http_client.fetch(probe_url, method="GET", follow_redirects=False,
                                        scope_check=scope_check)
        else:
            r = await http_client.fetch(
                url, method=m, body=urlencode({word: canary}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=False, scope_check=scope_check,
            )
        reflected = canary in r.text()
        len_delta = abs(len(r.body) - base_len)
        status_changed = r.status is not None and r.status != base_status
        if reflected:
            signal = "reflected"
        elif status_changed:
            signal = "status-change"
        elif len_delta >= _LEN_THRESHOLD:
            signal = "length-change"
        else:
            return None
        return {"param": word, "signal": signal, "status": r.status,
                "length": len(r.body), "length_delta": len_delta}

    results = await asyncio.gather(*[_probe(w) for w in words])
    found = [r for r in results if r]
    # reflected first, then behavioural
    order = {"reflected": 0, "status-change": 1, "length-change": 2}
    found.sort(key=lambda f: order.get(f["signal"], 9))
    return {
        "url": url, "method": m, "tested": len(words),
        "baseline": {"status": base_status, "length": base_len},
        "found_count": len(found), "found": found,
    }
