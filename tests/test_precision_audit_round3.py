"""Precision audit, round 2b — FP+TP pairs for the 19 verified detector fixes across the
10 detector groups the first workflow run's session limit had cut off.

Each test asserts BOTH halves: the false positive is suppressed (or the false negative
recovered) AND the true positive still fires. All FN-safe.
"""

import base64
import json
import ssl

import pytest

from moonmcp.findings import FindingsStore
from moonmcp.net import tls as tlsmod
from moonmcp.recon import buckets, csp, firebase, jslibs, openapi, origin
from moonmcp.recon import config_audit as ca
from moonmcp.recon import deserialize as dz
from moonmcp.web import behavior, crlf, debugpanel, exposure, oauth, redirect, saml, waf, waf_bypass


# --- shared fake HTTP response ---------------------------------------------
class _Resp:
    def __init__(self, status=200, body=b"", headers=None, set_cookies=None,
                 location=None, error=None, elapsed_ms=1.0):
        self.status = status
        self.body = body if isinstance(body, bytes) else body.encode()
        self._headers = dict(headers or {})
        if location:
            self._headers.setdefault("Location", location)
        self._set_cookies = list(set_cookies or [])
        self.error = error
        self.elapsed_ms = elapsed_ms

    def text(self, limit=None):
        return self.body.decode("utf-8", "replace")

    def header(self, name):
        return next((v for k, v in self._headers.items() if k.lower() == name.lower()), None)

    def headers_map(self):
        return dict(self._headers)

    @property
    def headers(self):
        return list(self._headers.items())

    def get_all(self, name):
        if name.lower() == "set-cookie":
            return list(self._set_cookies)
        v = self.header(name)
        return [v] if v else []


# ===========================================================================
# client-web
# ===========================================================================
def test_redirect_canary_must_be_the_authority_not_a_query_substring():
    p = redirect._points_to_canary
    c = redirect._CANARY
    # FP: a same-site absolute redirect that merely PRESERVES the payload in a query param
    assert p(f"https://www.app.test/dashboard?next=https://{c}/") is False
    assert p(f"https://app.test/login?returnTo=https://{c}/") is False
    # TP: the canary IS the destination authority (incl. the backslash/scheme variants)
    assert p(f"https://{c}/") is True
    assert p(f"//{c}/") is True
    assert p(f"/\\{c}/") is True
    assert p(f"https:\\\\{c}") is True


@pytest.mark.asyncio
async def test_debugpanel_soft404_echoing_path_does_not_confirm():
    class _EchoSoft404:
        async def fetch(self, url, **kw):
            # a soft-404 that echoes the requested path, as Express does
            return _Resp(404, f"Cannot GET {url.split('://',1)[-1]}".encode())

    assert await debugpanel.probe_debug_panels(_EchoSoft404(), "https://x.test") == []

    class _RealProfiler:
        async def fetch(self, url, **kw):
            if url.endswith("/_profiler"):
                return _Resp(200, b"<div class=sf-toolbar>sf-dump</div>")
            return _Resp(404, b"nope")

    hits = await debugpanel.probe_debug_panels(_RealProfiler(), "https://x.test")
    assert any(h["label"] == "Symfony profiler" for h in hits)


@pytest.mark.asyncio
async def test_exposure_env_and_reflog_need_structure_not_a_soft404():
    class _Site:
        def __init__(self, bodies):
            self.bodies = bodies

        async def fetch(self, url, **kw):
            for suffix, resp in self.bodies.items():
                if url.endswith(suffix):
                    return resp
            return _Resp(404, b"")

    # FP: a non-HTML 200 soft-404 (JS bundle with '='; JSON error for the reflog)
    fp = _Site({"/.env": _Resp(200, b"var a=1;var b=2;"),
                "/.git/logs/HEAD": _Resp(200, b'{"error":"not found"}')})
    res = await exposure.check_exposure(fp, "https://x.test/")
    assert all(not e.confirmed for e in res.exposed if e.path in ("/.env", "/.git/logs/HEAD"))
    assert res.git_exposed is False

    # TP: a real .env assignment and a real 40-hex reflog line still confirm
    tp = _Site({"/.env": _Resp(200, b"DB_PASSWORD=s3cr3t\nAPI_KEY=abc123"),
                "/.git/logs/HEAD": _Resp(200, b"0000000000000000000000000000000000000000 "
                                              b"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 x <x> 0 commit")})
    res2 = await exposure.check_exposure(tp, "https://x.test/")
    confirmed = {e.path for e in res2.exposed if e.confirmed}
    assert "/.env" in confirmed and "/.git/logs/HEAD" in confirmed and res2.git_exposed is True


# ===========================================================================
# behavior-waf
# ===========================================================================
def test_waf_block_signs_partition_keeps_generics_out_of_strong():
    # generic phrases must not be trusted on a 200 body alone
    for g in ("forbidden", "not acceptable", "security policy", "access denied"):
        assert g in waf_bypass._BLOCK_SIGNS_GENERIC and g not in waf_bypass._BLOCK_SIGNS_STRONG
    # discriminating tokens are the ones detect_waf trusts on a 200 body
    for s in ("ray id", "incident id", "mod_security"):
        assert s in waf_bypass._BLOCK_SIGNS_STRONG


@pytest.mark.asyncio
async def test_detect_waf_generic_phrase_on_200_is_not_a_block():
    class _Benign:
        async def fetch(self, url, **kw):
            # normal 200 page whose footer contains the generic phrase "Security Policy"
            return _Resp(200, b"<footer><a href=/legal>Security Policy</a> | Forbidden City tours</footer>")

    res = await waf.detect_waf(_Benign(), "https://x.test/", active=True)
    assert res.blocked_probe is False and res.detected == []

    class _RealWaf:
        async def fetch(self, url, **kw):
            if "moon=" in url:
                return _Resp(200, b"<h1>Access blocked</h1><p>Ray ID: 7a3f incident id 42</p>")
            return _Resp(200, b"ok")

    res2 = await waf.detect_waf(_RealWaf(), "https://x.test/", active=True)
    assert res2.blocked_probe is True


def test_behavior_generic_error_substrings_removed():
    for g in (" on line ", "Warning: ", "stack trace"):
        assert g not in behavior._ERROR_SIGNATURES
    assert "Fatal error" in behavior._ERROR_SIGNATURES   # specific markers kept


@pytest.mark.asyncio
async def test_behavior_marker_present_in_baseline_is_not_disclosure():
    class _Site:
        async def fetch(self, url, headers=None, **kw):
            # the NORMAL page already contains "Fatal error" as ordinary copy; the odd-input
            # probes return the same content -> not a leak. A DIFFERENT probe leaks a Traceback.
            if url.rstrip("/").endswith(("%c0%ae%c0%ae/", "moonmcp[]=1", "'\"><")) or "moonmcp[]" in url:
                if url.endswith("'\"><"):
                    return _Resp(500, b"Traceback (most recent call last): boom")
                return _Resp(200, b"<h1>Fatal error handling guide</h1>")
            return _Resp(200, b"<h1>Fatal error handling guide</h1>welcome")

    prof = await behavior.profile_behavior(_Site(), "https://x.test/")
    assert "Fatal error" not in prof.error_disclosure          # present in baseline → suppressed
    assert "Traceback (most recent call last)" in prof.error_disclosure  # genuinely new → reported


# ===========================================================================
# auth-tokens
# ===========================================================================
def test_oauth_flags_hs384_hs512_not_only_hs256():
    def issues(algs):
        return " ".join(f["issue"] for f in
                        oauth.analyze_oidc_metadata({"id_token_signing_alg_values_supported": algs}))
    assert "symmetric" in issues(["RS256", "HS384"]).lower()      # FN fixed
    assert "symmetric" in issues(["HS512"]).lower()
    assert "symmetric" not in issues(["RS256", "ES256"]).lower()  # asymmetric-only: no HMAC flag


def test_saml_reflected_in_rejection_is_not_an_acceptance():
    # a secure SP rejects (variant status != accepted status) but echoes the forged marker
    rej = saml.assess_variant(
        accepted=saml.Resp(200, 500), corrupted=saml.Resp(403, 400), variant=saml.Resp(403, 420),
        variant_body="SAML failed for moon-xsw-forged@x", accepted_body="alice", corrupted_body="alice",
        forged_marker="moon-xsw-forged@x")
    assert rej["reflected_forged_identity"] is True
    assert rej["matches_accepted_baseline"] is False   # server gate (reflected AND accepted) suppresses it
    # a genuine acceptance both reflects AND matches the accepted baseline
    acc = saml.assess_variant(
        accepted=saml.Resp(200, 500), corrupted=saml.Resp(403, 400), variant=saml.Resp(200, 505),
        variant_body="welcome moon-xsw-forged@x", accepted_body="alice", corrupted_body="alice",
        forged_marker="moon-xsw-forged@x")
    assert acc["reflected_forged_identity"] is True and acc["matches_accepted_baseline"] is True


# ===========================================================================
# exposure-vcs / crlf carryover already covered in round-2; datastore-cloud below
# ===========================================================================
def test_buckets_dump_regex_ignores_benign_backup_words():
    # FP: benign keys with a bare backup/snapshot word are NOT a DB dump
    assert buckets.extract_dump_keys(
        "<Key>src/components/__snapshots__/Button.test.js.snap</Key>"
        "<Key>images/backup/hero-2023.jpg</Key>") == []
    # TP: a real dump extension or dump-tool name still matches
    keys = buckets.extract_dump_keys(
        "<Key>db/mysqldump-2024.sql.gz</Key><Key>prod/users.bson</Key>")
    assert set(keys) == {"db/mysqldump-2024.sql.gz", "prod/users.bson"}


def test_deserialize_base64_two_byte_magic_needs_structure():
    # FP: an opaque base64 token that happens to decode to \x80\x02... is NOT pickle
    assert dz.detect_markers("gAJBcmVzdA") == []                     # decodes to \x80\x02'Arest'
    # TP: a real base64-transported pickle (ends with the STOP opcode '.') still fires
    real = base64.b64encode(b"\x80\x02}\x94.").decode()
    assert any(h.format == "python-pickle" for h in dz.detect_markers(real))
    # the 4-byte Java magic stays trusted even via base64 (specific enough)
    jb = base64.b64encode(b"\xac\xed\x00\x05\x00\x00").decode()
    assert any(h.format == "java-serialization" for h in dz.detect_markers(jb))


def test_firebase_open_rtdb_with_error_data_key_is_confirmed():
    # FN fixed: an open RTDB whose data has a top-level "error" node is NOT "protected"
    assert firebase.assess_rtdb(200, '{"error":true,"users":true}')["verdict"] == "confirmed"
    # a real deny is still classified protected
    assert firebase.assess_rtdb(401, '{"error":"Permission denied"}')["verdict"] == "protected"
    assert firebase.assess_rtdb(200, '{"error":"Permission denied"}')["verdict"] == "protected"


# ===========================================================================
# recon-fingerprint
# ===========================================================================
def test_config_audit_secret_key_with_benign_value_is_not_a_credential():
    def issues(k, v):
        return {f.issue for f in ca._rule_checks(k, v)}
    assert "exposed credential" not in issues("PASSWORD_MIN_LENGTH", "8")     # numeric
    assert "exposed credential" not in issues("JWT_ALGORITHM", "HS256")       # algorithm enum
    assert "exposed credential" not in issues("API_KEY_HEADER", "Authorization")   # header name
    assert "exposed credential" not in issues("TOKEN_HEADER_NAME", "X-Auth-Token")  # header name
    assert "exposed credential" not in issues("CREDENTIAL_PROVIDER", "env")   # provider token
    # TP: a real secret value still fires
    assert "exposed credential" in issues("DB_PASSWORD", "Sup3rS3cret!")
    assert "exposed credential" in issues("API_KEY", "wJalrXUtnFEMIK7MDENGbPxRfiCY")


def test_jslibs_branch_aware_bootstrap_boundary():
    # FP: Bootstrap 3.4.0/3.4.1 backported the fixes → patched, not vulnerable
    assert jslibs.scan("bootstrap-3.4.1.min.js") == []
    assert jslibs.scan("bootstrap-3.4.0.min.js") == []
    # TP: an unpatched 3.x and an unpatched 4.x still flag; a single-boundary lib unchanged
    assert [h["version"] for h in jslibs.scan("bootstrap-3.3.7.min.js")] == ["3.3.7"]
    assert [h["version"] for h in jslibs.scan("bootstrap-4.0.0.min.js")] == ["4.0.0"]
    assert [h["version"] for h in jslibs.scan("jquery-1.9.1.min.js")] == ["1.9.1"]
    assert jslibs.scan("jquery-3.6.0.min.js") == []   # patched jQuery unaffected


# ===========================================================================
# recon-surface
# ===========================================================================
def test_csp_bare_scheme_source_is_penalised():
    weak = csp.analyze_csp("script-src 'self' https:")
    assert weak["strength"] < 1.0                      # FN fixed: https: is a bypass
    assert any("scheme-only" in w[2] for w in weak["weaknesses"])
    strong = csp.analyze_csp("script-src 'self'")
    assert strong["strength"] == 1.0                   # a host-scoped policy is still full strength


def test_openapi_optional_security_is_public():
    spec = json.dumps({"openapi": "3.0.0", "paths": {
        "/data": {"get": {"security": [{}]}},               # optional auth → public
        "/secured": {"get": {"security": [{"apiKey": []}]}}}})
    res = openapi.parse_spec(spec)
    by_path = {e["path"]: e["auth_required"] for e in res["endpoints"]}
    assert by_path["/data"] is False and by_path["/secured"] is True
    assert res["public_operations"] >= 1


def test_origin_registrable_base_covers_more_cctld_suffixes():
    # FN/FP fixed: these public suffixes keep three labels (no candidate host under them)
    assert origin._registrable_base("example.org.br") == "example.org.br"
    assert origin._registrable_base("shop.co.id") == "shop.co.id"
    assert origin._registrable_base("api.com.ng") == "api.com.ng"
    # a normal 2-label domain is unchanged
    assert origin._registrable_base("www.example.com") == "example.com"


# ===========================================================================
# net-transport
# ===========================================================================
def test_tls_legacy_probe_can_offer_legacy_ciphers():
    # the fix lowers the client security level for the TLS1.0/1.1 probes so the handshake
    # can actually be offered on OpenSSL 3.x (SECLEVEL 2 otherwise refuses).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pytest.skip("this OpenSSL build rejects @SECLEVEL=0")
    assert ctx.get_ciphers()   # non-empty: legacy ciphers are now offerable
    # and _try_version applies it for the legacy versions (source-level guard)
    import inspect
    src = inspect.getsource(tlsmod._try_version)
    assert "SECLEVEL=0" in src and "TLSv1" in src


# ===========================================================================
# scoring-shape (findings severity-aware dedup/triage)
# ===========================================================================
def test_findings_dedupe_and_triage_keep_the_higher_severity():
    store = FindingsStore()
    store.add(target="api.test", severity="low", title="IDOR on orders", type="idor")
    store.add(target="api.test", severity="critical", title="IDOR on orders", type="idor")
    # triage (non-mutating) ranks the group at CRITICAL, not the earlier low lead
    tri = store.triage()
    assert tri["unique"] == 1
    assert tri["prioritized"][0]["finding"]["severity"] == "critical"
    # dedupe (mutating) keeps ONE finding, promoted to critical
    out = store.dedupe()
    assert out["remaining"] == 1
    assert store.list()[0].severity == "critical"


def test_crlf_round2_fix_still_holds():
    # guard against regression of the round-2 cookie-name fix while we touched neighbours
    assert crlf.assess({}, ["moonmcpcrlf=1; Path=/"]) is True
    assert crlf.assess({}, ["lang=moonSet-Cookie:moonmcpcrlf=1"]) is False
