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
                # a real reflog line: <40-hex old-sha> <40-hex new-sha> <who> <ts> <action>
                return _R(200, b"0000000000000000000000000000000000000000 "
                               b"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 Bob <b@x> 0 commit (initial)")
            return _R(404, b"")

    res2 = await check_exposure(_GitSite(), "https://x.test/")
    assert res2.git_exposed is True


# [core #19/#20] dedup keeps the higher-severity representative; clear() is
# subdomain-aware (same host scope as list()).
def test_findings_dedup_keeps_higher_severity_and_clear_is_subdomain_aware():
    from moonmcp.findings import FindingsStore
    fs = FindingsStore()
    fs.add(target="acme.com", severity="low", title="Same finding", type="x")
    fs.add(target="acme.com", severity="high", title="Same finding", type="x")
    uniq = fs.unique()
    assert len(uniq) == 1 and uniq[0].severity == "high"      # higher severity survives
    fs.add(target="sub.acme.com", severity="medium", title="Sub finding", type="y")
    assert fs.clear("acme.com") == 3                          # apex + subdomain findings
    assert fs.list("acme.com") == []


# [core #11] a malformed OIDC discovery doc with scalar (non-iterable) fields must
# not crash the probe.
def test_oidc_metadata_tolerates_scalar_fields():
    from moonmcp.web.oauth import analyze_oidc_metadata
    out = analyze_oidc_metadata({"response_types_supported": 1,       # int, not a list
                                 "code_challenge_methods_supported": 5})
    assert isinstance(out, list)                              # no TypeError


# [core #35] language filter is an exact token match, not a substring.
def test_techniques_by_language_is_exact_not_substring():
    from moonmcp.knowledge import techniques as tk
    # 'ava' is a substring of java/javascript but is not itself a language token.
    assert tk.by_language("ava") == []


# [core #34] a DDG uddg value is already decoded once — no second decode.
def test_ddg_real_url_no_double_decode():
    from moonmcp.intel.search import _real_url
    href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fx.com%2Fpath%253Fkeep&rut=abc"
    assert _real_url(href) == "https://x.com/path%3Fkeep"    # literal %3F survives


# [core #32] ModSecurity must not be fingerprinted on the generic phrase.
def test_modsecurity_not_matched_on_generic_phrase():
    from moonmcp.web import waf
    assert ("body", "not acceptable") not in waf._SIGNATURES["ModSecurity"]


# [core #9] registrable-domain derivation must handle multi-label public suffixes,
# so origin discovery doesn't emit candidate hosts under the public suffix.
def test_origin_registrable_base_handles_public_suffixes():
    from moonmcp.recon.origin import _registrable_base
    assert _registrable_base("example.com") == "example.com"
    assert _registrable_base("sub.example.com") == "example.com"
    assert _registrable_base("example.co.uk") == "example.co.uk"       # NOT "co.uk"
    assert _registrable_base("sub.example.co.uk") == "example.co.uk"
    assert _registrable_base("shop.example.com.au") == "example.com.au"


# ── DNS-rebinding: resolve-once, connect-by-pinned-IP ────────────────────────

def test_blocking_fetch_pins_to_ip_regardless_of_hostname(local_server, monkeypatch):
    # The HTTP client connects to the PINNED ip while keeping the URL hostname for
    # the Host header — so a rebinding swap between check and connect can't move the
    # socket. 'pinned.invalid' does not resolve; pinning to 127.0.0.1 must still reach
    # the local server, proving the socket used the pinned address.
    import json

    from moonmcp.net import http as H
    _base, port = local_server
    for v in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    res = H._blocking_fetch(f"http://pinned.invalid:{port}/echo", "GET", {}, None,
                            5.0, True, 65536, "127.0.0.1")
    assert res.status == 200
    assert json.loads(res.text())["host"].startswith("pinned.invalid")


@pytest.mark.asyncio
async def test_scan_ports_connects_to_pinned_host(local_server):
    from moonmcp.net import ports as P
    _base, port = local_server
    res = await P.scan_ports("unresolvable.invalid", [port], timeout=2.0, connect_host="127.0.0.1")
    assert res.host == "unresolvable.invalid"                       # display name preserved
    assert any(s.port == port and s.open for s in res.open_ports)   # reached via the pinned IP


def test_will_use_proxy_reads_env(monkeypatch):
    from moonmcp.net.http import _will_use_proxy
    for v in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
              "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(v, raising=False)
    assert _will_use_proxy("http", "example.com") is False          # no proxy → pin allowed
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:8080")
    assert _will_use_proxy("http", "example.com") is True           # proxied → skip pinning
    monkeypatch.setenv("no_proxy", "example.com")
    assert _will_use_proxy("http", "example.com") is False          # bypassed → pin allowed


# ── Gate-level pinned-IP contextvar (covers the raw-socket probes) ───────────

def test_pin_connect_host_matches_only_gated_host():
    from moonmcp import pin
    pin.set_pin("Example.COM", "93.184.216.34")
    assert pin.connect_host("example.com") == "93.184.216.34"    # case-insensitive match
    assert pin.connect_host("other.com") == "other.com"          # a different host is never pinned
    pin.set_pin("example.com", None)                             # block_private off → cleared
    assert pin.connect_host("example.com") == "example.com"
    pin.set_pin(None, None)


@pytest.mark.asyncio
async def test_gate_pins_resolved_ip_for_raw_socket_probes(fresh_context):
    # The scope gate resolves the target once and pins the IP, so raw-socket probes
    # (tls/jarm/desync/ws) connect to exactly that address via pin.connect_host.
    from moonmcp import pin
    from moonmcp.server import _require_scope
    fresh_context.scope.block_private = True
    fresh_context.scope._resolver = lambda h: ["93.184.216.34"]
    fresh_context.scope.add("gated.example")
    try:
        host = await _require_scope("gated.example", intrusive=False, tool="test")
        assert host == "gated.example"
        assert pin.connect_host("gated.example") == "93.184.216.34"   # gate pinned it
        assert pin.connect_host("elsewhere.example") == "elsewhere.example"
    finally:
        pin.set_pin(None, None)


# [session-hunt] a blanked permissive-capability flag must FAIL SAFE (off), not fall
# through to its True default (which would silently enable intrusive/external tools).
def test_env_bool_empty_disables_permissive_capability_flags(monkeypatch):
    assert cfg._env_bool("MOONMCP_TEST_CAP", True, on_empty=False) is True    # unset → default
    monkeypatch.setenv("MOONMCP_TEST_CAP", "")
    assert cfg._env_bool("MOONMCP_TEST_CAP", True, on_empty=False) is False   # blank → off
    monkeypatch.setenv("MOONMCP_TEST_CAP", "1")
    assert cfg._env_bool("MOONMCP_TEST_CAP", True, on_empty=False) is True    # explicit on
    # the real capability flags are wired fail-safe: blanking them disables the capability
    monkeypatch.setenv("MOONMCP_ALLOW_INTRUSIVE", "")
    monkeypatch.setenv("MOONMCP_ALLOW_EXTERNAL_TOOLS", "")
    s = cfg.load_settings()
    assert s.allow_intrusive is False and s.allow_external_tools is False
    # a safety flag still keeps its safe default when blanked
    monkeypatch.setenv("MOONMCP_BLOCK_PRIVATE", "")
    assert cfg.load_settings().block_private is True
