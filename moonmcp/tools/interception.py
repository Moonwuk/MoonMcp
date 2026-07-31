"""Interception surface — Burp-style repeater, intruder, passive scan & history.

Extracted from server.py. Manual/driven HTTP: replay a single request
(`http_repeater`), fuzz a template over a payload list (`intruder`), passively
score a captured response (`passive_scan`), and browse the recorded exchange
history (`http_history`). The shared `_record_exchange` recorder moves with them.
Importing this module registers the tools on the shared `mcp` instance.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .. import intercept as interceptmod
from ..context import to_dict
from ..mcp_core import (
    _require_scope,
    _scope_check,
    active_tool,
    get_context,
    mcp,
    safe_tool,
)
from ..scope import normalize_target


def _record_exchange(source: str, method: str, url: str, req_headers: dict,
                     req_body: bytes, result: Any, label: str = "") -> int:
    """Store a request/response pair in the session history; return its id."""

    ctx = get_context()
    ex = ctx.history.add(
        source=source, method=method, url=url, host=normalize_target(url),
        status=result.status, req_headers=req_headers or {}, req_body=req_body or b"",
        resp_headers=result.headers_map(), resp_body=result.body,
        resp_len=len(result.body), elapsed_ms=result.elapsed_ms, label=label,
    )
    return ex.id


@mcp.tool()
@active_tool(self_scoped=True)
async def http_repeater(url: str | None = None, method: str = "GET",
                        headers: dict[str, str] | None = None, body: str | None = None,
                        raw: str | None = None, follow_redirects: bool = False,
                        passive: bool = True, label: str = "") -> dict:
    """**Repeater** — send one fully-controlled HTTP request to an in-scope target
    and get the complete response back, so you can iterate on a payload.

    Provide either a `raw` HTTP/1.1 request (Burp-style: request line + headers +
    blank line + body; absolute URL or a `Host:` header) OR the structured form
    (`url` + `method` + `headers` + `body`). Returns status, response headers, the
    body (preview) and timing; by default also a quick `passive` scan (header
    grade, tech fingerprint, secret hits). Each call is recorded to `http_history`
    for replay. In scope only.
    """

    body_bytes: bytes | None
    if raw:
        method, url, parsed_headers, body_bytes = interceptmod.parse_raw_request(raw)
        merged_headers = {**parsed_headers, **(headers or {})}
    else:
        if not url or not url.strip():
            return {"error": "invalid_input", "detail": "pass a 'url' or a 'raw' request"}
        raw_t = url.strip()
        url = raw_t if "://" in raw_t else f"https://{raw_t}"
        merged_headers = headers or {}
        body_bytes = body.encode() if body else None

    await _require_scope(url, tool="http_repeater")
    ctx = get_context()
    result = await ctx.http.fetch(
        url, method=method, headers=merged_headers or None, body=body_bytes,
        follow_redirects=follow_redirects, max_redirects=ctx.settings.max_redirects,
        scope_check=_scope_check(),
    )
    ex_id = _record_exchange("repeater", method, url, merged_headers, body_bytes or b"",
                             result, label=label)
    out: dict[str, Any] = {
        "exchange_id": ex_id,
        "request": {"method": method, "url": url, "headers": merged_headers},
        "status": result.status,
        "reason": result.reason,
        "response_headers": result.headers_map(),
        "response_body_preview": result.text(4096),
        "response_bytes": len(result.body),
        "elapsed_ms": result.elapsed_ms,
    }
    if result.header("Location"):
        out["location"] = result.header("Location")
    if result.error:
        out["error"] = result.error
    if passive and result.status is not None:
        # Off the event loop: passive_findings runs the secret-scan regexes over up to
        # 500 KB of the (in-scope but attacker-controlled) response body — a large body
        # must not block concurrent tools (matches the crawl/secrets/binary offloads).
        out["passive"] = await asyncio.to_thread(interceptmod.passive_findings, result)
    return out


@mcp.tool()
@active_tool(self_scoped=True, intrusive=True)
async def intruder(template: str, payloads: list[str], marker: str = "§",
                   method: str = "GET", headers: dict[str, str] | None = None,
                   body: str | None = None, max_requests: int = 100) -> dict:
    """**Intruder** — fire a request `template` once per payload, substituting the
    `marker` (default `§`) with each payload, and diff the responses.

    Put the marker where the payload goes, e.g. ``https://host/search?q=§`` (or in
    `body` for POST). Returns, per payload: status, length, whether the payload was
    reflected in the response, and anomaly `flags` (status-change / length-outlier
    / reflected) versus a no-payload baseline — the leads for injection/IDOR entry
    points. Payloads are URL-encoded into the URL; the shared rate limiter caps
    real concurrency. Up to `max_requests` payloads. **Intrusive** (needs
    MOONMCP_ALLOW_INTRUSIVE) and in scope only.
    """

    from urllib.parse import quote

    if marker not in template and not (body and marker in body):
        return {"error": "invalid_input",
                "detail": f"marker {marker!r} not found in template or body"}
    base_url = template.replace(marker, "")
    raw_t = base_url.strip()
    base_url = raw_t if "://" in raw_t else f"https://{raw_t}"
    # Intruder is intrusive: this gates on MOONMCP_ALLOW_INTRUSIVE + scope.
    await _require_scope(template.replace(marker, ""), intrusive=True, tool="intruder")
    ctx = get_context()

    async def _one(payload: str) -> dict:
        enc = quote(payload, safe="")
        url = (template if "://" in template else f"https://{template}").replace(marker, enc)
        req_body = (body.replace(marker, payload).encode() if body else None)
        if not ctx.scope.is_in_scope(url):
            return interceptmod.IntruderResult(payload=payload, status=None, length=0,
                                               elapsed_ms=0.0, reflected=False,
                                               error="out_of_scope").__dict__
        try:
            r = await ctx.http.fetch(url, method=method, headers=headers, body=req_body,
                                     follow_redirects=False, scope_check=_scope_check())
        except Exception as exc:
            return interceptmod.IntruderResult(payload=payload, status=None, length=0,
                                               elapsed_ms=0.0, reflected=False,
                                               error=f"{type(exc).__name__}: {exc}").__dict__
        reflected = bool(payload) and payload.encode() in r.body
        return interceptmod.IntruderResult(
            payload=payload, status=r.status, length=len(r.body),
            elapsed_ms=r.elapsed_ms, reflected=reflected).__dict__

    # Baseline (empty payload) for diffing.
    base = await _one("")
    todo = list(dict.fromkeys(p for p in payloads if p))[:max(1, min(max_requests, 500))]
    results = await asyncio.gather(*[_one(p) for p in todo])

    base_status, base_len = base.get("status"), base.get("length", 0)
    for r in results:
        flags: list[str] = []
        if r.get("status") != base_status:
            flags.append("status-change")
        if base_len and abs(r.get("length", 0) - base_len) > max(50, base_len * 0.25):
            flags.append("length-outlier")
        if r.get("reflected"):
            flags.append("reflected")
        r["flags"] = flags
    interesting = [r for r in results if r["flags"] and not r.get("error")]
    return {
        "target": base_url,
        "baseline": {"status": base_status, "length": base_len},
        "sent": len(results),
        "interesting_count": len(interesting),
        "interesting": interesting[:100],
        "results": results[:200],
    }


@mcp.tool()
@active_tool("target")
async def passive_scan(target: str) -> dict:
    """**Passive scan** — fetch an in-scope URL once and run all of MoonMCP's
    passive analysers over the response in one call: HTTP security-header grade +
    issues, technology fingerprint, and exposed-secret hits (redacted). No probing
    or payloads — a single benign GET. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await ctx.http.fetch(
        url, follow_redirects=True, max_redirects=ctx.settings.max_redirects,
        scope_check=_scope_check(),
    )
    if result.status is None:
        return {"error": "unreachable", "detail": result.error, "url": url}
    _record_exchange("passive_scan", "GET", url, {}, b"", result)
    # Run the passive analysers (incl. the up-to-500 KB secret scan) off the event loop.
    pf = await asyncio.to_thread(interceptmod.passive_findings, result)
    return {"url": result.final_url or url, "status": result.status, **pf}


@mcp.tool()
@safe_tool
async def http_history(exchange_id: int | None = None, host: str | None = None,
                       limit: int = 50, clear: bool = False) -> dict:
    """Review the **request/response history** captured by `http_repeater`,
    `intruder` and `passive_scan` (like Burp's history). Pass an `exchange_id` for
    the full recorded pair, `host` to filter, `clear=true` to wipe. No traffic —
    reads the in-memory session log.
    """

    ctx = get_context()
    if clear:
        return {"cleared": ctx.history.clear()}
    if exchange_id is not None:
        ex = ctx.history.get(exchange_id)
        return to_dict(ex) if ex else {"error": "not_found", "detail": f"no exchange #{exchange_id}"}
    items = ctx.history.list(limit=limit, host=host)
    return {
        "count": ctx.history.count,
        "shown": len(items),
        "exchanges": [
            {"id": e.id, "source": e.source, "method": e.method, "url": e.url,
             "status": e.status, "resp_bytes": e.resp_len, "elapsed_ms": e.elapsed_ms,
             "label": e.label}
            for e in items
        ],
    }


# Active injection/exploitation probes live in moonmcp/tools/injection.py (imported below).
