"""Web-application vulnerability checks.

Extracted from server.py. Scope-gated HTTP-layer detectors: CORS, access-control
(IDOR / auth) and second-identity authz, GraphQL (introspection + injection),
WebSocket, hidden-parameter discovery, WAF detection, subdomain takeover, open
redirect and redirect-chain tracing, and VCS (.git) exposure + git forensics.
Importing this module registers them on the shared `mcp` instance.
"""

from __future__ import annotations

import re
from typing import Any

from ..context import to_dict
from ..mcp_core import (
    _connect_pin,
    _require_scope,
    _scope_check,
    _split_host_port,
    active_tool,
    get_context,
    mcp,
)
from ..recon import gitdump as gitdumpmod
from ..scope import normalize_target
from ..web import authz as authzmod
from ..web import cors as corsmod
from ..web import exposure as exposuremod
from ..web import graphql as graphqlmod
from ..web import graphqldeep as gqldeepmod
from ..web import params as paramsmod
from ..web import redirect as redirectmod
from ..web import takeover as takeovermod
from ..web import waf as wafmod
from ..web import websocket as wsmod


@mcp.tool()
@active_tool()
async def cors_audit(target: str) -> dict:
    """Test an in-scope URL for CORS misconfigurations: arbitrary-origin
    reflection, 'null' origin acceptance, and prefix/suffix/subdomain bypasses —
    flagged more severely when Access-Control-Allow-Credentials is also true.
    Sends benign GETs with crafted Origin headers. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await corsmod.audit_cors(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def access_control_check(target: str, method: str = "GET", body: str | None = None,
                               second_headers: dict[str, str] | None = None) -> dict:
    """Probe an in-scope URL for broken access control / IDOR by replaying the
    SAME request under multiple identities and diffing the responses:

    - **A** = the current engagement auth (`auth_set` — user A),
    - **B** = `second_headers` if given (a second, lower-priv user's headers/cookies),
    - **anon** = no credentials at all.

    If a protected resource returns a similar 2xx body to the anonymous or the
    other-user request, that is a strong broken-access-control / IDOR signal. The
    verdict is a lead to verify — it reports each identity's status/length and the
    body-similarity so you can judge. Set `auth_set` first for a meaningful A.
    In scope only; sends benign, identical requests (no payloads).
    """

    import hashlib
    from difflib import SequenceMatcher

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    bodyb = body.encode() if body else None
    m = method.upper()

    async def _probe(*, headers=None, suppress_auth=False):
        r = await ctx.http.fetch(url, method=m, headers=headers, body=bodyb,
                                 follow_redirects=False, suppress_auth=suppress_auth)
        snippet = r.body[:4096]
        return {
            "status": r.status,
            "length": len(r.body),
            "sha1": hashlib.sha1(snippet).hexdigest()[:12] if snippet else None,
            "_snippet": snippet,
            "error": r.error,
            "blocked": r.blocked_reason,
        }

    identities: dict[str, dict] = {}
    identities["auth_A"] = await _probe()  # current engagement auth
    if second_headers:
        identities["user_B"] = await _probe(headers=second_headers, suppress_auth=True)
    identities["anonymous"] = await _probe(suppress_auth=True)

    def _similar(a: dict, b: dict) -> float:
        if not a.get("_snippet") or not b.get("_snippet"):
            return 0.0
        return round(SequenceMatcher(None, a["_snippet"], b["_snippet"]).ratio(), 3)

    a = identities["auth_A"]
    concerns: list[str] = []
    comparisons: dict[str, dict] = {}
    for name in ("anonymous", "user_B"):
        other = identities.get(name)
        if not other:
            continue
        sim = _similar(a, other)
        comparisons[f"auth_A_vs_{name}"] = {
            "similarity": sim,
            "same_status": a["status"] == other["status"],
        }
        a_ok = a["status"] is not None and 200 <= a["status"] < 300
        other_ok = other["status"] is not None and 200 <= other["status"] < 300
        if a_ok and other_ok and sim >= 0.95:
            who = "an unauthenticated user" if name == "anonymous" else "a second user"
            concerns.append(
                f"{who} receives a response nearly identical to the authenticated one "
                f"(status {other['status']}, similarity {sim}) — possible broken access "
                f"control / IDOR; verify the resource is meant to be private to user A."
            )

    for v in identities.values():
        v.pop("_snippet", None)
    hint = None if ctx.auth.is_set() else "No engagement auth set — call auth_set first so 'auth_A' is authenticated."
    return {"target": url, "method": m, "identities": identities,
            "comparisons": comparisons, "concerns": concerns,
            "verdict": "review" if concerns else "no_obvious_idor", "hint": hint}


@mcp.tool()
@active_tool()
async def authz_probe(target: str, second_headers: dict[str, str] | None = None,
                      max_refs: int = 8) -> dict:
    """**Multi-step BOLA / IDOR chain** — the object-level authorization test a
    stateless scanner can't do. Set `auth_set` (owner = user A) and optionally pass
    `second_headers` (a lower-priv user B); this runs three GET-only signals:
    (1) **direct** — B/anon get the *same* object from the same URL; (2) **sibling
    sweep** — walk the id space (id±1, low ids) as B/anon and flag any object they
    read; (3) **multi-step chain** — extract the object ids the owner's response
    exposes, then fetch each as B/anon (owner response → cross-identity access).
    Read-only (never mutates — state change → Strix). Findings are `review` leads.
    In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await authzmod.probe_bola(ctx.http, url, b_headers=second_headers,
                                       max_refs=max_refs, scope_check=_scope_check())
    result["hint"] = (None if ctx.auth.is_set()
                      else "No engagement auth set — call auth_set first so the owner (A) is authenticated.")
    n = len(result.get("findings", []))
    result["note"] = (f"{n} object-authorization lead(s) — confirm the body is another user's private "
                      "object" if n else "no cross-identity object access observed")
    return result


@mcp.tool()
@active_tool()
async def graphql_check(target: str) -> dict:
    """Probe an in-scope host for GraphQL endpoints across common paths and test
    whether schema introspection is enabled (which leaks the full API surface).
    In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await graphqlmod.discover_graphql(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def graphql_probe(target: str, endpoint: str | None = None, batch_n: int = 5) -> dict:
    """**Deep GraphQL probing** — the classes that pay out even when introspection is
    OFF. Locates the endpoint (or use `endpoint=` to target one directly), then tests:
    **batch abuse** (an array of queries honoured in one request → rate-limit /
    brute-force amplifier, the batched-login credential-stuffing primitive),
    **field-suggestion schema recovery** (a typo'd field → *"Did you mean …?"* leaks
    real names, recovering the schema without introspection), and **aliases** (many
    operations per document). Nested-traversal **BOLA** is surfaced as a lead to
    confirm with `access_control_check` / Strix. Detection-only — benign queries, small
    batch, no mutations. Run `graphql_check` first for introspection. In scope only.
    """

    ctx = get_context()
    if endpoint:
        url = endpoint if "://" in endpoint else f"https://{endpoint}"
        await _require_scope(url, tool="graphql_probe")
    else:
        raw = target.strip()
        base = raw if "://" in raw else f"https://{raw}"
        disc = await graphqlmod.discover_graphql(ctx.http, base, scope_check=_scope_check())
        found = next((e for e in disc.endpoints if e.is_graphql), None)
        if not found:
            return {"target": target, "is_graphql": False,
                    "review": ["No GraphQL endpoint found on the common paths — pass endpoint= "
                               "if you know it, or run graphql_check."]}
        url = found.url
    result = await gqldeepmod.deep_probe(ctx.http, url, scope_check=_scope_check(),
                                         batch_n=max(2, min(batch_n, 20)))
    return to_dict(result)


@mcp.tool()
@active_tool()
async def ws_probe(target: str, probe_message: bool = False,
                   subprotocol: str | None = None) -> dict:
    """**WebSocket detection** — the surface most scanners skip. Speaks the RFC 6455
    handshake by hand (stdlib) to (1) confirm the URL is a real WebSocket endpoint
    (HTTP 101 + a valid `Sec-WebSocket-Accept`), and (2) run the flagship
    **Cross-Site WebSocket Hijacking (CSWSH)** check: repeat the handshake with a
    *foreign* `Origin` — if the server still upgrades, it doesn't validate Origin, so
    a cookie-authenticated socket is hijackable cross-site. Reports a **lead** (confirm
    the socket is cookie-authenticated and carries sensitive actions before reporting);
    weaponisation is routed to `promote_lead` / Strix.

    Accepts `ws://` / `wss://` (or http(s)/bare host — wss assumed). The handshake is
    as benign as an HTTP GET. `probe_message=True` (opt-in) additionally sends ONE
    clearly-marked benign text frame to check for echo/reflection — off by default so
    nothing is ever delivered into a live socket without consent. In scope only.
    """

    host, port, path, tls = wsmod.split_ws_url(target)
    if not host:
        return {"error": "invalid_target", "detail": f"no host in {target!r}"}
    result = await wsmod.probe_websocket(
        target, host=host, port=port, path=path, tls=tls,
        timeout=max(4.0, get_context().settings.timeout),
        probe_message=probe_message, subprotocol=subprotocol, connect_pin=_connect_pin())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def discover_parameters(target: str, method: str = "GET",
                              wordlist: list[str] | None = None) -> dict:
    """Discover **hidden parameters** on an in-scope URL: probe a wordlist of
    common param names with a benign canary and flag the ones the app reacts to —
    `reflected` (the value echoes back → candidate XSS/SSRF/injection entry point)
    or a behavioural `status-change` / `length-change` (the param is recognised).
    Hidden params are where XSS/SSRF/IDOR/SQLi entry points hide. Pass your own
    `wordlist` to override the defaults; `method` GET or POST. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await paramsmod.discover_parameters(
        ctx.http, url, method=method, wordlist=wordlist, scope_check=_scope_check(),
    )
    return result


@mcp.tool()
@active_tool()
async def waf_detect(target: str) -> dict:
    """Fingerprint an in-scope host's WAF/CDN from response headers, cookies and
    server strings (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, F5, ...). When
    intrusive mode is on, it also sends benign suspicious requests to see whether
    a protective layer trips. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await wafmod.detect_waf(
        ctx.http, url, scope_check=_scope_check(), active=ctx.settings.allow_intrusive
    )
    return to_dict(result)


@mcp.tool()
@active_tool()
async def takeover_check(target: str) -> dict:
    """Check an in-scope subdomain for a potential subdomain takeover: resolves
    the CNAME chain, matches it against a database of takeover-prone providers
    (S3, GitHub Pages, Heroku, Shopify, Azure, ...), and looks for the provider's
    'unclaimed resource' fingerprint (or a dangling DNS record). Results are
    triage signals — verify manually. In scope only.
    """

    host = normalize_target(target)
    ctx = get_context()
    result = await takeovermod.check_takeover(ctx.http, host, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def open_redirect(target: str) -> dict:
    """Test an in-scope URL for open-redirect flaws by injecting an external
    canary into the common redirect parameters (url, next, redirect, returnTo, …)
    and checking whether the server bounces to it via a Location header,
    meta-refresh or JS redirect. Redirects are not followed (the canary is never
    contacted). In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await redirectmod.check_open_redirect(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def trace_redirects(target: str, max_hops: int = 10) -> dict:
    """Follow and analyse an in-scope URL's **redirect chain** hop by hop: each
    hop's status, resolved Location, host and scheme, plus flags for
    `offsite-redirect`, `https-to-http-downgrade`, `redirect-leaves-scope`
    (recorded, not followed), `redirect-loop`, `meta-refresh` and `js-redirect`.
    Useful for auth/OAuth `redirect_uri` flows, SSRF-via-redirect and downgrade
    issues. Off-scope hops are reported but never contacted. In scope only.
    """

    from urllib.parse import urljoin, urlsplit

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    start_host = normalize_target(url)
    ctx = get_context()
    hops: list[dict] = []
    flags: set[str] = set()
    current = url
    seen: set[str] = set()
    final = url
    for _ in range(max(1, min(max_hops, 20))):
        r = await ctx.http.fetch(current, method="GET", follow_redirects=False)
        sp = urlsplit(current)
        hop: dict[str, Any] = {"url": current, "status": r.status,
                               "host": sp.hostname, "scheme": sp.scheme}
        final = current
        if r.status is None:
            hop["error"] = r.error
            hops.append(hop)
            break
        location = r.header("Location") if (300 <= r.status < 400) else None
        if location:
            nxt = urljoin(current, location)
            nsp = urlsplit(nxt)
            hop["location"] = nxt
            in_scope = ctx.scope.is_in_scope(nxt)
            hop["location_in_scope"] = in_scope
            if nsp.hostname and nsp.hostname != sp.hostname:
                flags.add("offsite-redirect")
            if sp.scheme == "https" and nsp.scheme == "http":
                flags.add("https-to-http-downgrade")
            hops.append(hop)
            if nxt in seen:
                flags.add("redirect-loop")
                final = nxt
                break
            seen.add(nxt)
            if not in_scope:
                flags.add("redirect-leaves-scope")  # report, don't follow
                final = nxt
                break
            current = nxt
            continue
        # terminal page — check for client-side redirects
        body = r.text(4096)
        mr = re.search(r'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', body, re.IGNORECASE)
        if mr:
            hop["meta_refresh"] = urljoin(current, mr.group(1))
            flags.add("meta-refresh")
        if re.search(r'(?:window\.)?location(?:\.href|\.replace\(|\s*=)', body, re.IGNORECASE):
            flags.add("js-redirect")
        hops.append(hop)
        break
    return {"start": url, "start_host": start_host, "hop_count": len(hops),
            "final_url": final, "flags": sorted(flags), "hops": hops}


@mcp.tool()
@active_tool()
async def vcs_exposure(target: str) -> dict:
    """Check an in-scope host for exposed VCS/config artefacts (.git, .svn, .hg,
    .env, .DS_Store). Confirms real exposure by validating each file's content
    signature (not just a 200), extracts the git remote URL and recent commit
    log when a .git is exposed. Source disclosure via an exposed .git is
    high-impact. In scope only.
    """

    host, port = _split_host_port(target, 443)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    base = raw if "://" in raw else f"{scheme}://{host}"
    ctx = get_context()
    result = await exposuremod.check_exposure(ctx.http, base, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def git_forensics(target: str, max_objects: int = 60) -> dict:
    """**Git-history forensics** on an exposed `.git` — the deep follow-up to
    `vcs_exposure` and a stable-Critical source. Reconstructs history from what the
    server already serves (read-only GETs; nothing written) and mines it for secrets:

    - `.git/config` remote URLs embedding **credentials** (`user:token@host`),
    - `.git/logs/HEAD` reflog → commit SHAs + **author names/emails** + messages,
    - `.git/index` → the **tracked file list** (flags `.env` / `id_rsa` / `*.sql` /
      `credentials` — what secrets exist), parsed from the binary DIRC format,
    - a **bounded loose-object walk** (`objects/xx/…`, zlib-inflate → commit → tree →
      blob) running the secret scanner over each blob and commit message.

    Packed history (`objects/pack/*.pack`, delta-compressed) is **detected and
    reported**, not parsed — run git-dumper / delegate to Strix for a full clone.
    Secrets are redacted; treat each as a lead (confirm it's live/not rotated).
    `max_objects` caps the walk (default 60). In scope only.
    """

    host, port = _split_host_port(target, 443)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    base = raw if "://" in raw else f"{scheme}://{host}"
    ctx = get_context()
    result, hits = await gitdumpmod.git_forensics(
        ctx.http, base, scope_check=_scope_check(),
        max_objects=max(1, min(max_objects, 300)))
    # Fold the scanner's redacted hits (blobs/config/reflog/messages) into the report.
    for h in hits:
        result.secrets.append({"type": h.type, "source": h.source,
                               "redacted": h.redacted, "fp_risk": h.fp_risk})
    return to_dict(result)
