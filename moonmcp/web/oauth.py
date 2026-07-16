"""OIDC / OAuth discovery recon — one GET maps the auth surface and flags weak posture.

Every compliant OpenID provider publishes a discovery document at
``/.well-known/openid-configuration`` (RFC 8414 adds
``/.well-known/oauth-authorization-server``). It leaks the issuer, all endpoints,
and — most usefully — the supported response types, PKCE methods and signing
algorithms, which reveal weak configuration (implicit grant, no PKCE, ``none`` /
``HS256`` signing, plaintext issuer, issuer↔jwks host mix-up). Sends only benign
GETs; the analyser is pure and separately testable.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlencode, urljoin, urlsplit

from ..net.http import HttpClient

# Attacker-controlled host the crafted redirect_uri variants point at. Requests are
# sent with redirects DISABLED, so this host is never actually contacted — a 3xx whose
# Location lands here proves the authorization endpoint accepted an attacker redirect_uri.
_OAUTH_CANARY = "moonmcp-oauth-canary.example"

_WELL_KNOWN = ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")
_ENDPOINT_KEYS = (
    "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint",
    "registration_endpoint", "introspection_endpoint", "revocation_endpoint",
    "end_session_endpoint", "device_authorization_endpoint",
)


@dataclass
class OidcResult:
    url: str
    discovered: bool = False
    document_url: str | None = None
    issuer: str | None = None
    endpoints: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    error: str | None = None


def _as_list(v: object) -> list:
    """Coerce an OIDC metadata field to a list. The spec says these fields are
    arrays, but a malformed/hostile discovery document (fetched from the target's
    ``.well-known/openid-configuration``) may send a scalar — iterating a bare int
    raises TypeError and aborts the whole probe, so normalise to [] instead."""

    return v if isinstance(v, list) else []


def analyze_oidc_metadata(meta: dict) -> list[dict]:
    """Flag weak-posture indicators in an OIDC/OAuth discovery document (pure)."""

    out: list[dict] = []

    def add(sev: str, issue: str, detail: str) -> None:
        out.append({"severity": sev, "issue": issue, "detail": detail})

    rts = [str(r).lower() for r in _as_list(meta.get("response_types_supported"))]
    if any("token" in r for r in rts):  # 'token' / 'id_token token' => implicit flow
        add("medium", "implicit grant enabled",
            "response_types_supported offers the implicit flow (access token in the URL fragment)")
    pkce = [str(m).lower() for m in _as_list(meta.get("code_challenge_methods_supported"))]
    if not pkce:
        add("medium", "PKCE not advertised",
            "no code_challenge_methods_supported — PKCE may be unsupported (auth-code interception)")
    elif "s256" not in pkce:
        add("medium", "PKCE downgradeable", f"only weak PKCE methods advertised: {pkce} (no S256)")
    algs = [str(a).lower() for a in _as_list(meta.get("id_token_signing_alg_values_supported"))]
    if "none" in algs:
        add("high", "id_token signing alg 'none' allowed",
            "id_token_signing_alg_values_supported includes none — unsigned id_tokens accepted")
    if "hs256" in algs:
        add("medium", "id_token HS256 offered",
            "symmetric HS256 signing advertised — alg-confusion / weak-secret surface")
    issuer = str(meta.get("issuer") or "")
    if issuer.startswith("http://"):
        add("medium", "issuer over plaintext http", f"issuer is {issuer!r} — cleartext token exchange")
    jwks = str(meta.get("jwks_uri") or "")
    if issuer and jwks:
        ih, jh = urlsplit(issuer).hostname, urlsplit(jwks).hostname
        if ih and jh and ih != jh:
            add("low", "jwks_uri host differs from issuer",
                f"issuer host {ih} vs jwks_uri host {jh} — possible mix-up surface")
    tem = [str(m).lower() for m in (meta.get("token_endpoint_auth_methods_supported") or [])]
    if "none" in tem:
        add("info", "public clients allowed",
            "token_endpoint_auth_methods_supported includes none (public client)")
    return out


def redirect_uri_variants(legit_host: str, canary: str = _OAUTH_CANARY) -> list[tuple[str, str]]:
    """Attacker `redirect_uri` values that exploit the common allow-list weaknesses
    (open host, subdomain/suffix, `@`-host, path-traversal, backslash confusion)."""

    lh = legit_host or "app.example.com"
    return [
        ("attacker-host", f"https://{canary}/callback"),
        ("subdomain-suffix", f"https://{lh}.{canary}/callback"),
        ("userinfo-host", f"https://{lh}@{canary}/callback"),
        ("path-traversal", f"https://{lh}/callback/..;/@{canary}/"),
        ("backslash-confusion", f"https://{lh}\\@{canary}/"),
    ]


def _lands_on_canary(location: str, canary: str = _OAUTH_CANARY) -> bool:
    """Does a redirect ``Location`` navigate to the attacker canary host?"""

    if not location:
        return False
    try:
        h = (urlsplit(location).hostname or "").lower()
    except ValueError:
        return False
    return h == canary or h.endswith("." + canary)


async def probe_redirect_uri_bypass(client: HttpClient, authorization_endpoint: str, *,
                                    client_id: str | None = None,
                                    scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Replay attacker `redirect_uri` variants at the authorization endpoint (redirects
    disabled) and flag any that make the server 3xx to the canary — an OAuth
    redirect_uri bypass → auth-code/token theft → account takeover."""

    ep = authorization_endpoint
    legit_host = urlsplit(ep).hostname or ""
    findings: list[dict] = []
    for label, ruri in redirect_uri_variants(legit_host):
        params = {"response_type": "code", "redirect_uri": ruri, "scope": "openid",
                  "state": "moonoauthcanary"}
        if client_id:
            params["client_id"] = client_id
        sep = "&" if "?" in ep else "?"
        test_url = f"{ep}{sep}{urlencode(params)}"
        r = await client.fetch(test_url, follow_redirects=False, timeout=12.0, scope_check=scope_check)
        if r.status is not None and 300 <= r.status < 400 and _lands_on_canary(r.header("Location") or ""):
            findings.append({
                "kind": "oauth_redirect_bypass", "technique": label, "redirect_uri": ruri,
                "location": (r.header("Location") or "")[:200], "severity": "high", "verdict": "review",
                "detail": f"the authorization endpoint 3xx-redirected to an attacker redirect_uri "
                          f"({label}) — OAuth redirect_uri allow-list bypass: an attacker steals the "
                          "auth code/token → account takeover. Confirm the code/token is delivered.",
            })
    return findings


async def probe_oidc(client: HttpClient, base_url: str, *,
                     scope_check: Callable[[str], bool] | None = None) -> OidcResult:
    """Fetch the OIDC/OAuth discovery document (trying both well-known paths) and
    return the endpoints + weak-config findings."""

    result = OidcResult(url=base_url)
    for path in _WELL_KNOWN:
        doc_url = urljoin(base_url, path)
        if scope_check is not None and not scope_check(doc_url):
            continue
        r = await client.fetch(doc_url, follow_redirects=True, timeout=12.0, scope_check=scope_check)
        if r.status != 200 or not r.body:
            continue
        try:
            meta = json.loads(r.text(limit=200_000))
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict) or "issuer" not in meta:
            continue
        result.discovered = True
        result.document_url = r.final_url or doc_url
        result.issuer = str(meta.get("issuer"))
        result.endpoints = {k: meta.get(k) for k in _ENDPOINT_KEYS if meta.get(k)}
        result.findings = analyze_oidc_metadata(meta)
        return result
    result.error = "no OIDC/OAuth discovery document found"
    return result
