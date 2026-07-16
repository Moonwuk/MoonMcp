"""Precision audit, round 2 — FP+TP pairs for the seven verified detector fixes.

Each test asserts BOTH halves of a fix: the false positive is now suppressed (or the
false negative recovered) AND the true positive still fires. All are FN-safe.
"""

import re

import pytest

from moonmcp import confirm as confmod
from moonmcp.web import authflow as af
from moonmcp.web import authz as az
from moonmcp.web import crlf
from moonmcp.web import ormleak as orm
from moonmcp.web import ssrf_meta as sm


# ---------------------------------------------------------------------------
# 1. authz — plural-fold FN: companies<->company (and -ies/-ses) must chain
# ---------------------------------------------------------------------------
def test_collection_compatible_folds_ies_and_ses_plurals():
    # a collection and its irregular plural now collapse alike (both sides canonicalise)
    assert az._collection_compatible("company", "companies") is True
    assert az._collection_compatible("category", "categories") is True
    assert az._collection_compatible("activity", "activities") is True
    assert az._collection_compatible("status", "statuses") is True
    assert az._collection_compatible("address", "addresses") is True
    # a foreign collection still does NOT chain into the slot
    assert az._collection_compatible("product", "companies") is False
    assert az._collection_compatible("user", "categories") is False


class _R:
    def __init__(self, status, body):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body
        self.error = None
        self.blocked_reason = None

    def text(self, limit=None):
        return self.body.decode()


class _CompanyPluralApp:
    """/companies/100 (owner) exposes company_id=88213 (SAME collection, plural slot); a
    non-owner can read /companies/88213 (another org). The multi-step chain must fold
    companies<->company and chain it — the old single-'s' strip silently dropped it."""

    async def fetch(self, url, *, method="GET", headers=None, body=None,
                    suppress_auth=False, **kwargs):
        m = re.search(r"/companies/(\d+)", url)
        if not m:
            return _R(404, "not found")
        cid = m.group(1)
        if not suppress_auth and cid == "100":
            return _R(200, '{"id":100,"owner":"A","company_id":88213,"data":"owner-company-100-xxxx"}')
        if suppress_auth and cid == "88213":
            return _R(200, '{"id":88213,"owner":"Z","data":"another-org-company-88213-xxxxxxxx"}')
        return _R(403, "forbidden")


@pytest.mark.asyncio
async def test_multistep_chains_plural_collection_company_id_into_companies_slot():
    res = await az.probe_bola(_CompanyPluralApp(), "https://x.test/companies/100",
                              b_headers={"Cookie": "b=1"})
    owner_refs = {f["owner_ref"] for f in res["findings"] if f["kind"] == "multistep_bola"}
    assert "88213" in owner_refs   # companies<->company folds → chained IDOR fires (FN fixed)


# ---------------------------------------------------------------------------
# 2. ssrf_meta — generic-signature FP (AWS/DO/k8s) + Azure system-assigned FN
# ---------------------------------------------------------------------------
def _tgt(provider):
    return next(t for t in sm.CLOUD_METADATA_TARGETS if t["provider"] == provider)


def test_aws_root_generic_prose_no_longer_confirms():
    prose = "Assign an IAM role to William and set the server hostname in Miami."
    assert len(sm.scan_metadata_leak(_tgt("AWS (metadata root)"), prose)) < 2   # FP suppressed
    real = "ami-id\nami-launch-index\nhostname\niam/\ninstance-id\ninstance-type\n"
    assert len(sm.scan_metadata_leak(_tgt("AWS (metadata root)"), real)) >= 2   # TP preserved


def test_digitalocean_generic_prose_no_longer_confirms():
    prose = "Our API interfaces are available in every region."
    assert len(sm.scan_metadata_leak(_tgt("DigitalOcean"), prose)) < 2          # FP suppressed
    real = '{"droplet_id":2756294,"hostname":"web01","interfaces":{"public":[]},"region":"nyc3"}'
    assert len(sm.scan_metadata_leak(_tgt("DigitalOcean"), real)) >= 2          # TP preserved


def test_azure_system_assigned_token_now_confirms():
    body = ('{"access_token":"eyJ0eXAiOiJKV1Qi","expires_in":"3599","expires_on":"1700000000",'
            '"resource":"https://management.azure.com/","token_type":"Bearer"}')
    assert len(sm.scan_metadata_leak(_tgt("Azure"), body)) >= 2                 # FN fixed (no client_id)
    assert len(sm.scan_metadata_leak(_tgt("Azure"), "please provide an access token")) < 2


def test_k8s_api_index_reflected_swagger_no_longer_confirms():
    swagger = '{"openapi":"3.0.0","paths":{"/healthz":{"get":{}},"/users":{"get":{}}}}'
    assert len(sm.scan_metadata_leak(_tgt("Kubernetes API server (API index)"), swagger)) < 2
    real = '{"paths":["/api","/api/v1","/apis","/apis/apps","/healthz","/version"]}'
    assert len(sm.scan_metadata_leak(_tgt("Kubernetes API server (API index)"), real)) >= 2


# ---------------------------------------------------------------------------
# 4. ormleak — reflection FP: an echoed CONTROL_NONE must not fake a filter
# ---------------------------------------------------------------------------
def test_ormleak_reflection_guard():
    # a genuine relational filter: "all" (many rows) vs "none" (empty) differ, not echoed
    assert orm.assess_lookup(((200, 900), (200, 900)), ((200, 120), (200, 120))) is True
    # reflection FP: the +17-byte "none" delta is just the echoed 17-char CONTROL_NONE
    refl_all, refl_none = ((200, 500), (200, 500)), ((200, 517), (200, 517))
    assert orm.assess_lookup(refl_all, refl_none) is True                       # differs on its face
    assert orm.assess_lookup(refl_all, refl_none, none_reflected=True) is False  # guard suppresses


# ---------------------------------------------------------------------------
# 3. nosqli — $where boolean payloads must be equal length (echo ≠ oracle)
# ---------------------------------------------------------------------------
def test_nosqli_where_payloads_equal_length_and_oracle_still_works():
    from moonmcp.web import nosqli as nq
    # the fix: the two $where expressions are equal length, so an endpoint that merely
    # echoes the posted JSON produces identical true/false response lengths → no oracle.
    assert len(nq.WHERE_TRUE["$where"]) == len(nq.WHERE_FALSE["$where"])
    echo_t = (nq.Resp(200, 100), nq.Resp(200, 100))
    echo_f = (nq.Resp(200, 100), nq.Resp(200, 100))   # equal-length echo → same length
    assert nq.assess_where(echo_t, echo_f) is None                     # FP suppressed
    # a real server-side-JS oracle (true matches all rows, false none) still differs
    real_t = (nq.Resp(200, 900), nq.Resp(200, 900))
    real_f = (nq.Resp(401, 40), nq.Resp(401, 40))
    assert nq.assess_where(real_t, real_f) is not None                 # TP preserved


# ---------------------------------------------------------------------------
# 6. crlf — cookie marker must match a cookie NAME, not a reflected substring
# ---------------------------------------------------------------------------
def test_crlf_cookie_matches_name_not_substring():
    # real split: the injected 'Set-Cookie: moonmcpcrlf=1' parses as its own cookie
    assert crlf.assess({}, ["moonmcpcrlf=1; Path=/"]) is True
    # SAFE server strips the CRLF but reflects the payload into another cookie's VALUE:
    # the marker is only a substring of the 'lang=' cookie, not a cookie name → not a hit
    assert crlf.assess({}, ["lang=moonSet-Cookie:moonmcpcrlf=1; Path=/"]) is False


# ---------------------------------------------------------------------------
# 7. authflow — a bare verify/confirm/activate/magic link is a lead, not confirmed
# ---------------------------------------------------------------------------
def test_authflow_bare_word_link_is_review_not_confirmed():
    for body in ('{"help":"https://help.acme.test/verify-your-account"}',
                 '{"asset":"https://cdn.acme.test/activate-widget.js"}'):
        links = [f for f in af.scan_response_leak(body) if f["kind"] == "reset_link_in_body"]
        assert links, body
        assert all(f["verdict"] == "review" and f["severity"] == "medium" for f in links), body


def test_authflow_token_bearing_link_still_confirmed():
    for body in ('{"link":"https://acme.test/verify?token=abc123def456"}',
                 '{"link":"https://acme.test/reset-password/xyz789abc"}',
                 '{"link":"https://acme.test/set?code=998877"}'):
        links = [f for f in af.scan_response_leak(body) if f["kind"] == "reset_link_in_body"]
        assert links and all(f["verdict"] == "confirmed" and f["severity"] == "high"
                             for f in links), body


# ---------------------------------------------------------------------------
# 5. secondorder — a lone transient error must not reach "confirmed"
# ---------------------------------------------------------------------------
def _mysql_sig(text):
    return [{"matched": "sql syntax", "technology": "MySQL"}] if "syntax" in (text or "").lower() else []


def test_secondorder_error_lane_alone_is_not_reflected_so_not_confirmed():
    from moonmcp.web import secondorder as so
    tag = "moon2oABCD1234"
    control = so.ReadObs(200, "ok normal page")
    error = so.ReadObs(500, "You have an error in your SQL syntax")   # tag NOT reflected
    same = so.ReadObs(200, "ok normal page")
    hit = so.assess_read(tag, control, error, same, same, _mysql_sig)
    assert hit is not None and hit["error_signatures"]
    assert hit["reflected"] is False                                  # error != reflection
    # the server now feeds tag-reflection (not has_error) as the corroboration signal:
    verdict = confmod.evaluate(injection_hits=["sqli/second-order"],
                               reflected=hit["reflected"], status_changed=hit["boolean_differential"])
    assert verdict["verdict"] != "confirmed"                          # a lone transient error → "likely"

    # a genuinely reflected boolean-lane hit still confirms (TP preserved)
    r = so.ReadObs(200, f"echo {tag} here")
    r2 = so.ReadObs(200, f"echo {tag} here longer body with more rows aaaaaaaa")
    hit2 = so.assess_read(tag, control, so.ReadObs(200, "ok"), r, r2, _mysql_sig)
    assert hit2 is not None and hit2["reflected"] is True and hit2["boolean_differential"] is True
    v2 = confmod.evaluate(injection_hits=["sqli/second-order"],
                          reflected=hit2["reflected"], status_changed=hit2["boolean_differential"])
    assert v2["verdict"] == "confirmed"
