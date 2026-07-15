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
