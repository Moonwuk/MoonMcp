"""Regression tests for the bug-hunt fixes — each pins one confirmed defect."""

import pytest

from moonmcp import cvss
from moonmcp.intel import asn
from moonmcp.recon import headers, infra
from moonmcp.web import redirect, takeover


# -- CVSS 3.1 Scope:Changed impact formula -----------------------------------
def test_cvss_scope_changed_uses_31_formula():
    # AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H is 7.0/High under CVSS 3.1 (the 3.0
    # formula wrongly yielded 6.9/Medium — a dropped severity band).
    r = cvss.base_score(vector="CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H")
    assert r["score"] == 7.0
    assert r["severity"] == "high"


def test_cvss_scope_unchanged_unaffected():
    # S:U uses 6.42*ISS in both 3.0 and 3.1 — must stay a critical 9.8.
    r = cvss.base_score(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert r["score"] == 9.8 and r["severity"] == "critical"


# -- infra patch-drift version dedup -----------------------------------------
def test_patch_drift_keeps_prefix_versions():
    # "nginx/1.2" is a string prefix of "nginx/1.25.1" but a DIFFERENT version —
    # the fleet is drifting and it must be reported.
    samples = [
        {"server": "nginx/1.2", "backend": "a", "date_epoch": 1.0, "elapsed_ms": 1},
        {"server": "nginx/1.25.1", "backend": "b", "date_epoch": 1.0, "elapsed_ms": 1},
    ]
    r = infra.cluster_backends(samples)
    assert r["patch_drift"] is True
    assert set(r["server_versions"]) == {"nginx/1.2", "nginx/1.25.1"}


def test_patch_drift_still_drops_bare_product_name():
    # "nginx" vs "nginx/1.25.1" is the same product, not two versions.
    samples = [
        {"server": "nginx", "backend": "a", "date_epoch": 1.0, "elapsed_ms": 1},
        {"server": "nginx/1.25.1", "backend": "b", "date_epoch": 1.0, "elapsed_ms": 1},
    ]
    assert infra.cluster_backends(samples)["patch_drift"] is False


# -- ASN cloud detection: whole-word, not substring --------------------------
def test_detect_cloud_no_substring_false_positive():
    assert asn._detect_cloud("Lawson, Inc.") is None      # "aws" ⊂ "lawson"
    assert asn._detect_cloud("Amazon.com, Inc.") == "AWS"
    assert asn._detect_cloud("Google LLC") == "Google Cloud"   # prefix marker "goog"
    assert asn._detect_cloud("Contabo GmbH") is None


# -- cookie flags tested as attributes, not substrings -----------------------
class _Resp:
    def __init__(self, url, cookies):
        self.url = url
        self.final_url = url
        self._cookies = cookies

    def get_all(self, name):
        return self._cookies if name == "set-cookie" else []


def test_cookie_value_containing_secure_is_not_masked():
    # `mode=insecure` contains "secure" but the Secure ATTRIBUTE is absent.
    findings = headers._analyze_cookies(_Resp("https://x.test", ["mode=insecure; Path=/"]))
    details = " ".join(f.detail for f in findings)
    assert "Secure flag" in details


def test_cookie_with_secure_attribute_not_flagged():
    findings = headers._analyze_cookies(
        _Resp("https://x.test", ["sid=abc; Secure; HttpOnly; SameSite=Lax"]))
    assert not any("Secure flag" in f.detail for f in findings)


# -- meta-refresh open-redirect: attribute order must not matter --------------
def test_meta_refresh_matches_reversed_attribute_order():
    tag = '<meta content="0; url=//evil.example/x" http-equiv="refresh">'
    m = redirect._META_REFRESH_RE.search(tag)
    assert m is not None and m.group(1) == "//evil.example/x"
    # canonical order still works
    m2 = redirect._META_REFRESH_RE.search('<meta http-equiv="refresh" content="0;url=/next">')
    assert m2 is not None and m2.group(1) == "/next"


# -- subdomain-takeover false-positive / false-negative ----------------------
def _patch_resolve(monkeypatch, *, records=None, a=None, aaaa=None, canonical=None):
    class _Dns:
        def __init__(self):
            self.records = records or {}
            self.a = a or []
            self.aaaa = aaaa or []
            self.canonical_name = canonical
            self.error = None

    async def _fake(host, rdtypes=None, http_client=None):
        return _Dns()

    monkeypatch.setattr(takeover, "resolve", _fake)


class _Client:
    def __init__(self, status, body):
        self._status, self._body = status, body

    async def fetch(self, *a, **k):
        client = self

        class _R:
            status = client._status

            def text(self, limit=None):
                return client._body
        return _R()


@pytest.mark.asyncio
async def test_takeover_no_fp_on_plain_404(monkeypatch):
    # A/record host (no takeover-prone CNAME) whose page is a normal 404 must
    # NOT be reported as a confirmed takeover.
    _patch_resolve(monkeypatch, a=["1.2.3.4"])
    res = await takeover.check_takeover(_Client(404, "<h1>404 Not Found</h1>"), "www.example.com")
    assert res.vulnerable is False


@pytest.mark.asyncio
async def test_takeover_body_only_hit_is_low_confidence_lead(monkeypatch):
    # A specific fingerprint with no CNAME anchor is a lead, not a confirmation.
    _patch_resolve(monkeypatch, a=["1.2.3.4"])
    res = await takeover.check_takeover(
        _Client(404, "Sorry, this shop is currently unavailable"), "shop.example.com")
    assert res.vulnerable is False
    assert res.confidence == "low"


@pytest.mark.asyncio
async def test_takeover_dangling_cname_detected(monkeypatch):
    # Dangling CNAME → NXDOMAIN target with no A/AAAA: querying CNAME first must
    # preserve the record so the takeover is flagged.
    _patch_resolve(monkeypatch,
                   records={"CNAME": ["dead-env.elasticbeanstalk.com"]},
                   canonical="dead-env.elasticbeanstalk.com")
    res = await takeover.check_takeover(_Client(None, ""), "sub.example.com")
    assert res.dangling_dns is True
    assert res.vulnerable is True
    assert res.service == "AWS/Elastic Beanstalk"
