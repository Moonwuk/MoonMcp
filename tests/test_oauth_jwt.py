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


# -- JWT alg-confusion forgery (RS256 -> HS256 using the public key as secret) ----
_PUB_KEY = ("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"
           "-----END PUBLIC KEY-----\n")


def _make_rs_token(payload: dict, kid: str | None = None) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.fake-rsa-signature-not-verified-here"


def test_forge_alg_confusion_flips_alg_and_signs_with_public_key():
    token = _make_rs_token({"sub": "victim", "admin": False})
    forged = jwtmod.forge_alg_confusion(token, _PUB_KEY)
    a = jwtmod.analyze_jwt(forged)
    assert a.algorithm == "HS256"
    assert a.payload == {"sub": "victim", "admin": False}
    # the forged signature must verify under the public-key-as-HMAC-secret
    h_seg, p_seg, sig = forged.split(".")
    expected = _b64(hmac.new(_PUB_KEY.encode(), f"{h_seg}.{p_seg}".encode(), hashlib.sha256).digest())
    assert sig == expected


def test_forge_alg_confusion_preserves_kid():
    token = _make_rs_token({"sub": "1"}, kid="key-42")
    forged = jwtmod.forge_alg_confusion(token, _PUB_KEY)
    header = json.loads(base64.urlsafe_b64decode(forged.split(".")[0] + "=="))
    assert header["kid"] == "key-42" and header["alg"] == "HS256"


def test_forge_alg_confusion_supports_hs384_512():
    token = _make_rs_token({"sub": "1"})
    forged = jwtmod.forge_alg_confusion(token, _PUB_KEY, alg="HS512")
    assert jwtmod.analyze_jwt(forged).algorithm == "HS512"


def test_forge_alg_confusion_rejects_bad_alg_and_bad_token():
    with pytest.raises(ValueError, match="unsupported"):
        jwtmod.forge_alg_confusion(_make_rs_token({}), _PUB_KEY, alg="RS256")
    with pytest.raises(ValueError, match="not a JWT"):
        jwtmod.forge_alg_confusion("not-a-jwt", _PUB_KEY)


@pytest.mark.asyncio
async def test_jwt_alg_confusion_tool(fresh_context):
    token = _make_rs_token({"sub": "victim", "role": "user"})
    res = await srv.jwt_alg_confusion(token=token, public_key_pem=_PUB_KEY)
    assert res["algorithm"] == "HS256" and "forged_token" in res
    a = jwtmod.analyze_jwt(res["forged_token"])
    assert a.payload == {"sub": "victim", "role": "user"}


@pytest.mark.asyncio
async def test_jwt_alg_confusion_tool_bad_token_reports_error(fresh_context):
    res = await srv.jwt_alg_confusion(token="garbage", public_key_pem=_PUB_KEY)
    assert res["error"] == "invalid_input"


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
