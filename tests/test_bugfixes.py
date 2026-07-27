"""Regression tests for the whole-project bug hunt — each pins a confirmed, fixed bug."""

import ssl

import pytest

from moonmcp import config as cfg
from moonmcp.intel import oast
from moonmcp.memory import MemoryStore
from moonmcp.net.http import _build_opener
from moonmcp.recon import config_audit, firebase
from moonmcp.scope import ScopeManager
from moonmcp.web import nosqli, redirect


# [#1] IPv4-mapped IPv6 literal must not defeat an IPv4 exclusion/allow.
def test_ipv4_mapped_ipv6_does_not_bypass_exclusion():
    s = ScopeManager(block_private=False)
    s.add("::/0")
    s.exclude("198.51.100.0/24")
    assert not s.is_in_scope("198.51.100.9")
    assert not s.is_in_scope("::ffff:198.51.100.9")   # the mapped twin was a bypass


# [#6] The SSRF connect-guard must fail CLOSED when the resolver errors.
def test_connect_guard_fails_closed_on_resolver_error():
    def boom(_host):
        raise RuntimeError("resolver down")

    s = ScopeManager(block_private=True, resolver=boom)
    reason = s.blocked_connect_reason("internal.example.com")
    assert reason and "fail-closed" in reason.lower()
    # a clean public resolution is allowed; a private one is blocked
    assert ScopeManager(block_private=True,
                        resolver=lambda h: ["8.8.8.8"]).blocked_connect_reason("x.example") is None
    assert ScopeManager(block_private=True,
                        resolver=lambda h: ["127.0.0.1"]).blocked_connect_reason("x.example") is not None


# [#2] The HTTP opener must not carry File/FTP/Data handlers, and fetch must refuse
# a non-HTTP(S) scheme (no local-file read / crash on a file:// redirect).
def test_opener_drops_file_ftp_data_handlers():
    names = {type(h).__name__ for h in _build_opener(ssl.create_default_context()).handlers}
    assert not (names & {"FileHandler", "FTPHandler", "DataHandler"})


@pytest.mark.asyncio
async def test_fetch_refuses_non_http_scheme(fresh_context):
    res = await fresh_context.http.fetch("file:///etc/passwd", follow_redirects=False)
    assert res.status is None
    assert "scheme" in (res.blocked_reason or res.error or "").lower()


# [#11] nosqli.assess_operator must not trust a flip against a noisy control.
def test_nosqli_requires_reproducible_control():
    R = nosqli.Resp
    noisy = (R(status=200, length=10), R(status=500, length=10))       # control disagrees
    twin = (R(status=500, length=10), R(status=500, length=10))
    assert nosqli.assess_operator(noisy, twin) is None
    stable = (R(status=401, length=10), R(status=401, length=10))
    assert nosqli.assess_operator(stable, twin) is not None            # now a real flip


# [#13] backslash-confusion open-redirect payloads are recognised.
def test_redirect_backslash_canary():
    c = redirect._CANARY
    assert redirect._points_to_canary(f"/\\{c}/")
    assert redirect._points_to_canary(f"https:\\\\{c}")
    assert not redirect._points_to_canary("/local/path")


# [#15] an empty 200 body is NOT a confirmed open Firebase RTDB.
def test_firebase_empty_body_not_confirmed():
    assert firebase.assess_rtdb(200, "") is None
    assert firebase.assess_rtdb(200, "   ") is None
    assert firebase.assess_rtdb(200, '{"users":{}}')["verdict"] == "confirmed"
    assert firebase.assess_rtdb(200, "null")["verdict"] == "confirmed"


# [#16] an empty/error OAST poll envelope is not counted as an interaction.
def test_oast_empty_envelope_not_counted():
    assert oast.parse_interactions('{"data": null, "aes_key": "x"}') == []
    assert oast.parse_interactions('{"error": "boom"}') == []
    hits = oast.parse_interactions('{"data":[{"protocol":"http","unique-id":"a"}]}')
    assert len(hits) == 1
    # a bare object that DOES look like an interaction still counts
    assert len(oast.parse_interactions('{"protocol":"dns","remote-address":"1.2.3.4"}')) == 1


# [#20] a real secret that merely contains "null" is not suppressed as a placeholder.
def test_placeholder_only_matches_specific_markers():
    assert not config_audit._looks_placeholder("aZnullQ2p9Kx8vT")
    assert config_audit._looks_placeholder("changeme123")
    assert config_audit._looks_placeholder("my_placeholder_value")
    assert config_audit._looks_placeholder("null")


# [#21] a safety flag defaults safely on an unrecognised value.
def test_env_bool_unknown_keeps_default(monkeypatch):
    monkeypatch.setenv("MOONMCP_TEST_FLAG", "enabled")
    assert cfg._env_bool("MOONMCP_TEST_FLAG", True) is True     # not silently flipped to False
    monkeypatch.setenv("MOONMCP_TEST_FLAG", "garbage")
    assert cfg._env_bool("MOONMCP_TEST_FLAG", True) is True
    assert cfg._env_bool("MOONMCP_TEST_FLAG", False) is False
    monkeypatch.setenv("MOONMCP_TEST_FLAG", "off")
    assert cfg._env_bool("MOONMCP_TEST_FLAG", True) is False    # explicit falsey still works


# [#17] an untrusted upsert must not downgrade a curated memory item.
def test_memory_upsert_never_downgrades_curated_trust():
    m = MemoryStore()
    i1 = m.add(kind="finding", title="Admin panel exposed", target="acme.com", trust="curated",
               body="verified")
    i2 = m.add(kind="finding", title="admin panel exposed", target="ACME.com", trust="untrusted",
               body="scraped claim")
    assert i1 == i2                                              # same dedup key → upsert
    assert m.get(i1)["trust"] == "curated"                      # trust NOT downgraded
