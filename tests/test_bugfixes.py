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


# ═══════════════════════════════════════════════════════════════════════════
# Deep core bug-hunt (adversarial, multi-agent verified). Each test pins one
# confirmed defect from the scope / http / config / recon core.
# ═══════════════════════════════════════════════════════════════════════════

# [core #3] a scheme-less "user@host" authority must not smuggle a host past the
# SSRF guard — normalize_target now strips userinfo the way urlsplit does for URLs.
def test_scope_strips_userinfo_from_bare_authority():
    from moonmcp import scope as sc
    assert sc.normalize_target("user@169.254.169.254") == "169.254.169.254"
    assert sc.normalize_target("user:pass@10.0.0.5:8080") == "10.0.0.5"
    assert sc.normalize_target("bob@[::1]:443") == "::1"
    assert sc.is_blocked_address(sc.normalize_target("user@169.254.169.254")) is True
    s = ScopeManager(block_private=True)
    assert s.evaluate("user@169.254.169.254")[0] is False                 # literal SSRF block fires
    assert s.blocked_connect_reason("user@169.254.169.254") is not None   # connect guard fires


# [core #18] blanking a safety flag (MOONMCP_BLOCK_PRIVATE=) must keep the safe
# default, not silently disable it — an empty value now reads as "leave at default".
def test_env_bool_empty_string_keeps_default(monkeypatch):
    monkeypatch.setenv("MOONMCP_TEST_FLAG", "")
    assert cfg._env_bool("MOONMCP_TEST_FLAG", True) is True
    monkeypatch.setenv("MOONMCP_TEST_FLAG", "   ")
    assert cfg._env_bool("MOONMCP_TEST_FLAG", True) is True
    monkeypatch.setenv("MOONMCP_TEST_FLAG", "false")     # explicit falsey still disables
    assert cfg._env_bool("MOONMCP_TEST_FLAG", True) is False


# [core #23] an illegal CR/LF header value must yield a clean HttpResult(error=…),
# never crash fetch() with an uncaught ValueError from http.client.
def test_blocking_fetch_illegal_header_does_not_crash(local_server):
    from moonmcp.net.http import _blocking_fetch
    base, _ = local_server
    res = _blocking_fetch(f"{base}/", "GET", {"X-Bad": "a\r\nInjected: 1"},
                          None, 5.0, True, 4096)
    assert res is not None                    # did not raise
    assert res.status is None and res.error   # rejected gracefully


# [core #5] an empty-signature VCS path returning a 200 HTML soft-404 must NOT be
# confirmed as an exposed .git (the HTML guard now covers empty signatures too).
@pytest.mark.asyncio
async def test_exposure_empty_signature_soft404_not_confirmed():
    from moonmcp.web.exposure import check_exposure

    class _R:
        def __init__(self, s, b):
            self.status, self.body = s, b

        def text(self, limit=None):
            return self.body.decode()

    class _SoftSite:
        async def fetch(self, url, **kw):
            return _R(200, b"<!doctype html><html><body>app shell</body></html>")

    res = await check_exposure(_SoftSite(), "https://x.test/")
    assert res.git_exposed is False
    assert all(not e.confirmed for e in res.exposed)

    class _GitSite:                            # a REAL commit log (plain text) still confirms
        async def fetch(self, url, **kw):
            if url.endswith("/.git/logs/HEAD"):
                return _R(200, b"0000000000000000000000000000000000000000 "
                               b"abc1234 Bob <b@x> 0 commit (initial)")
            return _R(404, b"")

    res2 = await check_exposure(_GitSite(), "https://x.test/")
    assert res2.git_exposed is True
