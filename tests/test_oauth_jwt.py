"""OIDC discovery probe + JWT offline HMAC crack / alg=none forge."""

import base64
import hashlib
import hmac
import json

import pytest

from moonmcp import server as srv
from moonmcp.web import jwt as jwtmod
from moonmcp.web import oauth as oauthmod


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_hs_token(secret: str, alg: str = "HS256", payload: dict | None = None) -> str:
    algs = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    h = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload or {"sub": "1", "admin": False}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), algs[alg]).digest())
    return f"{h}.{p}.{sig}"


# -- JWT offline crack / forge -----------------------------------------------
def test_jwt_crack_recovers_weak_secret():
    assert jwtmod.crack_hmac_secret(_make_hs_token("secret")) == "secret"


def test_jwt_crack_custom_wordlist_and_alg():
    tok = _make_hs_token("hunter2", alg="HS512")
    assert jwtmod.crack_hmac_secret(tok, ["nope", "hunter2"]) == "hunter2"


def test_jwt_crack_no_match_returns_none():
    assert jwtmod.crack_hmac_secret(_make_hs_token("Zx9!_very_long_unguessable_value")) is None


def test_jwt_crack_ignores_non_hmac_alg():
    # RS256 header — not HMAC; must return None (never a false "crack").
    tok = _b64(b'{"alg":"RS256"}') + "." + _b64(b'{"a":1}') + ".zzz"
    assert jwtmod.crack_hmac_secret(tok) is None


def test_forge_alg_none_preserves_payload():
    forged = jwtmod.forge_alg_none(_make_hs_token("secret", payload={"admin": True}))
    assert forged.endswith(".")  # empty signature
    a = jwtmod.analyze_jwt(forged)
    assert a.algorithm == "none" and a.payload == {"admin": True}


@pytest.mark.asyncio
async def test_jwt_crack_tool(local_server, fresh_context):
    res = await srv.jwt_crack(token=_make_hs_token("changeme"))
    assert res["hmac_secret_found"] is True
    assert res["secret"] == "changeme" and res["severity"] == "critical"
    assert res["alg_none_forgery"].endswith(".")


# -- OIDC discovery analyser -------------------------------------------------
_WEAK_OIDC = {
    "issuer": "http://idp.example.com",
    "authorization_endpoint": "http://idp.example.com/authorize",
    "token_endpoint": "http://idp.example.com/token",
    "jwks_uri": "https://keys.other.com/jwks",
    "response_types_supported": ["code", "token", "id_token token"],
    "code_challenge_methods_supported": ["plain"],
    "id_token_signing_alg_values_supported": ["RS256", "HS256", "none"],
    "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
}


def test_analyze_oidc_flags_weak_posture():
    issues = {f["issue"] for f in oauthmod.analyze_oidc_metadata(_WEAK_OIDC)}
    assert "implicit grant enabled" in issues
    assert "id_token signing alg 'none' allowed" in issues
    assert "issuer over plaintext http" in issues
    assert "PKCE downgradeable" in issues
    assert "jwks_uri host differs from issuer" in issues
    assert "public clients allowed" in issues


def test_analyze_oidc_clean_doc_has_no_findings():
    good = {
        "issuer": "https://idp.example.com",
        "jwks_uri": "https://idp.example.com/jwks",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }
    assert oauthmod.analyze_oidc_metadata(good) == []


class _Resp:
    def __init__(self, status, body):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body
        self.final_url = None

    def text(self, limit=None):
        return self.body.decode()


class _Client:
    def __init__(self, mapping):
        self._mapping = mapping

    async def fetch(self, url, **kwargs):
        for suffix, resp in self._mapping.items():
            if url.endswith(suffix):
                return resp
        return _Resp(404, "")


@pytest.mark.asyncio
async def test_probe_oidc_discovers_and_flags():
    client = _Client({"/.well-known/openid-configuration": _Resp(200, json.dumps(_WEAK_OIDC))})
    res = await oauthmod.probe_oidc(client, "https://idp.example.com")
    assert res.discovered is True
    assert res.issuer == "http://idp.example.com"
    assert "token_endpoint" in res.endpoints
    assert any(f["issue"] == "id_token signing alg 'none' allowed" for f in res.findings)


@pytest.mark.asyncio
async def test_probe_oidc_absent_document():
    res = await oauthmod.probe_oidc(_Client({}), "https://no-oidc.example.com")
    assert res.discovered is False and res.error


@pytest.mark.asyncio
async def test_new_identity_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert {"jwt_crack", "oauth_probe"} <= tools
