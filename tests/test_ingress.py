"""Ingress-controller fingerprint + offline version→CVE mapping."""

import pytest

from moonmcp import server as srv
from moonmcp.net.http import HttpResult
from moonmcp.net.tls import TlsResult
from moonmcp.recon import ingress as ing


def _resp(headers=None, body=b"", status=200, url="https://t.example/"):
    return HttpResult(
        url=url, final_url=url, status=status, reason="OK",
        headers=list(headers or []), body=body, elapsed_ms=1.0,
    )


# -- version_status (branch-aware) -------------------------------------------
_NIGHTMARE = ("1.11.5", "1.12.1")


@pytest.mark.parametrize("version,expected", [
    ("1.11.4", "vulnerable"),
    ("1.11.5", "patched"),
    ("1.12.0", "vulnerable"),   # the load-bearing case: 1.12.0 IS vulnerable
    ("1.12.1", "patched"),
    ("1.10.3", "vulnerable"),   # branch older than every fix
    ("1.13.0", "patched"),      # branch newer than every fix
    (None, "unknown"),
    ("not-a-version", "unknown"),
])
def test_version_status_branches(version, expected):
    assert ing.version_status(version, _NIGHTMARE) == expected


def test_version_status_single_branch():
    assert ing.version_status("2.3.1", ("2.3.2",)) == "vulnerable"
    assert ing.version_status("2.3.2", ("2.3.2",)) == "patched"
    assert ing.version_status("2.4.0", ("2.3.2",)) == "patched"


# Multi-major fixes with a minor that isn't itself a listed branch (a "gap"): the
# old code fell through to "unknown" and hid a live vuln / mislabelled a patched one.
@pytest.mark.parametrize("version,expected", [
    # Traefik CVE-2025-32431 fixed in 2.11.24 (v2 line) and 3.3.6 (v3 line).
    ("3.2.0", "vulnerable"),    # v3 minor below the 3.3 fix branch — never patched
    ("3.3.6", "patched"),
    ("3.4.0", "patched"),       # v3 minor above the fix branch — shipped with the fix
    ("2.10.0", "vulnerable"),   # v2 minor below the 2.11 fix branch
    ("2.12.0", "patched"),      # v2 minor above the 2.11 fix branch
    ("1.7.0", "vulnerable"),    # whole major below every fixed major
    ("4.0.0", "patched"),       # whole major above every fixed major
])
def test_version_status_gap_between_branches(version, expected):
    assert ing.version_status(version, ("2.11.24", "3.3.6")) == expected


def test_version_status_ingress_nginx_zero_to_one_gap():
    # CVE-2021-25742 fixed in 0.49.1 (0.x line) and 1.0.1 (1.x line).
    fixed = ("0.49.1", "1.0.1")
    assert ing.version_status("0.50.0", fixed) == "patched"      # after the 0.49 fix in the 0.x line
    assert ing.version_status("0.49.0", fixed) == "vulnerable"
    assert ing.version_status("1.0.0", fixed) == "vulnerable"    # 1.0 branch, before 1.0.1
    assert ing.version_status("2.0.0", fixed) == "patched"       # major above every fix


def test_version_status_multi_minor_same_major_unaffected():
    # Envoy CVE-2023-27487: five per-minor backports in the 1.x line. The fix must
    # not be treated as a same-major "ceiling" — 1.23.6 (its own branch's fix) is patched.
    fixed = ("1.22.9", "1.23.6", "1.24.4", "1.25.3", "1.26.0")
    assert ing.version_status("1.23.6", fixed) == "patched"
    assert ing.version_status("1.23.0", fixed) == "vulnerable"
    assert ing.version_status("1.27.0", fixed) == "patched"      # newer than the newest backport
    assert ing.version_status("1.20.0", fixed) == "vulnerable"   # older than the oldest backport


def test_known_cves_sorted_by_documented_key():
    # The list must be ordered by the documented key: severity, then unauth, then
    # version_status, then cvss — most-severe first, never status-first.
    status_rank = {"vulnerable": 2, "unknown": 1, "patched": 0}
    sev_rank = ing._SEVERITY_RANK
    for controller, version in [("ingress-nginx", "1.11.4"), ("Istio", "1.9.0"), ("Kong", "2.1.0")]:
        cves = ing.known_cves(controller, version)
        keyed = [
            (sev_rank.get(c["severity"], 0), c["unauth"],
             status_rank.get(c["version_status"], 0), c["cvss"])
            for c in cves
        ]
        assert keyed == sorted(keyed, reverse=True), f"{controller} not most-severe-first"


# -- known_cves --------------------------------------------------------------
def test_known_cves_unknown_version_lists_candidates():
    cves = ing.known_cves("ingress-nginx", None)
    assert cves, "ingress-nginx must have a curated CVE set"
    assert all(c["version_status"] == "unknown" for c in cves)
    # Most-severe first: IngressNightmare keystone leads.
    assert cves[0]["id"] == "CVE-2025-1974"
    assert cves[0]["severity"] == "critical"
    assert cves[0]["unauth"] is True


def test_known_cves_istio_implies_envoy():
    ids = {c["id"] for c in ing.known_cves("Istio", None)}
    assert "CVE-2021-31920" in ids          # Istio
    assert "CVE-2023-27487" in ids          # Envoy (implied)


def test_known_cves_version_narrows_status():
    # A modern Kong: both curated CVEs are patched.
    modern = {c["id"]: c["version_status"] for c in ing.known_cves("Kong", "3.4.1")}
    assert modern["CVE-2021-27306"] == "patched"
    # An old Kong: the JWT-plugin traversal is live.
    old = {c["id"]: c["version_status"] for c in ing.known_cves("Kong", "2.1.0")}
    assert old["CVE-2021-27306"] == "vulnerable"


def test_known_cves_unknown_controller_empty():
    assert ing.known_cves("Nginx-but-not-ingress", None) == []


# -- classify ----------------------------------------------------------------
def test_classify_ingress_nginx_default_backend():
    main = _resp(headers=[("Server", "nginx")])
    unmatched = _resp(body=b"default backend - 404", status=404)
    rep = ing.classify(main, unmatched=unmatched)
    assert rep["controller"] == "ingress-nginx"
    assert rep["version"] is None
    assert any(c["id"] == "CVE-2025-1974" for c in rep["applicable_cves"])
    assert rep["admin_surface"]            # points at :10254 / admission webhook
    assert any("metrics" in n for n in rep["notes"])


def test_classify_kong_via_header_captures_version():
    main = _resp(headers=[("Via", "kong/2.1.0"), ("X-Kong-Proxy-Latency", "1")])
    rep = ing.classify(main)
    assert rep["controller"] == "Kong"
    assert rep["version"] == "2.1.0"
    live = {c["id"]: c["version_status"] for c in rep["applicable_cves"]}
    assert live["CVE-2021-27306"] == "vulnerable"


def test_classify_istio_from_server_header():
    main = _resp(headers=[("Server", "istio-envoy"),
                          ("X-Envoy-Upstream-Service-Time", "3")])
    rep = ing.classify(main)
    assert rep["controller"] == "Istio"
    ids = {c["id"] for c in rep["applicable_cves"]}
    assert "CVE-2021-39155" in ids and "CVE-2023-27487" in ids


def test_classify_fake_certificate_and_admission_san():
    main = _resp(headers=[("Server", "nginx")])
    cert = TlsResult(
        host="t.example", port=443, connected=True,
        subject={"commonName": "Kubernetes Ingress Controller Fake Certificate"},
        subject_alt_names=["ingress-nginx-controller-admission.ingress-nginx.svc"],
    )
    rep = ing.classify(main, cert=cert)
    tells = {t["tell"] for t in rep["cert_tells"]}
    assert "fake_certificate" in tells
    assert "admission_webhook_san" in tells
    # The cert alone is enough to call it ingress-nginx.
    assert rep["controller"] == "ingress-nginx"
    assert any("unauthenticated" in n for n in rep["notes"])


def test_classify_unknown_stack_is_empty():
    rep = ing.classify(_resp(headers=[("Server", "gws")]))
    assert rep["controller"] is None
    assert rep["applicable_cves"] == []


# -- admin exposure sweep ----------------------------------------------------
def test_assess_admin_hit():
    assert ing.assess_admin_hit(200, '{"routers": {}, "middlewares": {}}', ['"routers"'])
    assert not ing.assess_admin_hit(200, "unrelated page", ['"routers"'])
    assert not ing.assess_admin_hit(404, '"routers"', ['"routers"'])   # not 200
    assert not ing.assess_admin_hit(None, "", ['"routers"'])


def test_admin_endpoints_are_readonly_and_cover_controllers():
    ctrls = {e["controller"] for e in ing.ADMIN_ENDPOINTS}
    assert {"Traefik", "Kong", "ingress-nginx"} <= ctrls
    # every swept path is read-only — never a mutating control endpoint
    for e in ing.ADMIN_ENDPOINTS:
        assert "quitquit" not in e["path"] and "config_dump" not in e["path"]


# -- e2e: the tools are wired and scope-gated --------------------------------
@pytest.mark.asyncio
async def test_ingress_fingerprint_scope_gated(fresh_context):
    res = await srv.ingress_fingerprint(target="definitely-not-in-scope.invalid")
    assert res["error"] == "out_of_scope"
    assert res["action"]


@pytest.mark.asyncio
async def test_ingress_admin_exposure_scope_gated(fresh_context):
    res = await srv.ingress_admin_exposure(target="definitely-not-in-scope.invalid")
    assert res["error"] == "out_of_scope"
