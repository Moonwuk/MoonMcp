"""Behavioural infrastructure detectors — pure analysers + end-to-end eval."""

import pytest

from moonmcp import server as srv
from moonmcp.recon import infra


# -- pure analysers ---------------------------------------------------------
def test_cluster_backends_detects_fleet_and_patch_drift():
    samples = [
        {"server": "nginx/1.24.0", "backend": "a", "date_epoch": 1000.0, "elapsed_ms": 10},
        {"server": "nginx/1.25.1", "backend": "b", "date_epoch": 1009.0, "elapsed_ms": 12},
        {"server": "nginx/1.24.0", "backend": "a", "date_epoch": 1000.0, "elapsed_ms": 11},
    ]
    r = infra.cluster_backends(samples)
    assert r["distinct_backends"] == 2 and r["load_balanced"] is True
    assert r["patch_drift"] is True
    assert set(r["server_versions"]) == {"nginx/1.24.0", "nginx/1.25.1"}
    assert r["clock_skew_seconds"] == 9.0
    assert r["concerns"]


def test_cluster_backends_single():
    r = infra.cluster_backends([{"server": "nginx", "date_epoch": 1.0, "elapsed_ms": 5}])
    assert r["distinct_backends"] == 1 and r["load_balanced"] is False
    assert r["patch_drift"] is False
    assert r["content_drift"] is False


def test_cluster_backends_flags_content_drift():
    # same product/version, but two nodes serve a different ETag for the same URL
    samples = [
        {"server": "nginx", "backend": "a", "etag": "v1", "date_epoch": 1.0, "elapsed_ms": 5},
        {"server": "nginx", "backend": "b", "etag": "v2", "date_epoch": 1.0, "elapsed_ms": 5},
    ]
    r = infra.cluster_backends(samples)
    assert r["content_drift"] is True and len(r["content_versions"]) == 2
    assert any("content/build drift" in c for c in r["concerns"])


def test_cluster_backends_header_order_discriminates_backends():
    # identical Server, but different response header ORDER → two distinct backends
    samples = [
        {"server": "nginx", "header_order": ("server", "date", "etag"), "date_epoch": 1.0, "elapsed_ms": 5},
        {"server": "nginx", "header_order": ("date", "server", "etag"), "date_epoch": 1.0, "elapsed_ms": 5},
    ]
    r = infra.cluster_backends(samples)
    assert r["distinct_backends"] == 2 and r["load_balanced"] is True


def test_parse_http_date():
    assert infra.parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT") == pytest.approx(1445412480, abs=1)
    assert infra.parse_http_date(None) is None
    assert infra.parse_http_date("not a date") is None


def test_ratelimit_summary_flags_bypass():
    r = infra.ratelimit_summary([200, 200, 429], first_block=3, retry_after="30", bypass_reset=True)
    assert r["verdict"] == "rate_limited" and r["ip_header_bypass"] is True
    assert any("X-Forwarded-For" in c for c in r["concerns"])


# -- end-to-end against the behaving test server ----------------------------
@pytest.mark.asyncio
async def test_backend_probe_detects_lb_and_drift(local_server, fresh_context):
    base, _ = local_server
    res = await srv.backend_probe(target=f"{base}/lb", samples=8)
    assert res["distinct_backends"] == 2
    assert res["load_balanced"] is True
    assert res["patch_drift"] is True


@pytest.mark.asyncio
async def test_vhost_probe_detects_open_host_and_reflection(local_server, fresh_context):
    base, _ = local_server
    res = await srv.vhost_probe(target=f"{base}/vhost")
    assert res["host_validated"] is False
    assert res["host_header_reflected"] is True
    assert res["concerns"]
    # new signals present (http baseline → SNI n/a, no envoy-path trust)
    assert "envoy_original_path_trusted" in res
    assert res["sni_host_enforced"] is None  # http target, not https


@pytest.mark.asyncio
async def test_ratelimit_probe_detects_limit_and_ip_bypass(local_server, fresh_context):
    base, _ = local_server
    res = await srv.ratelimit_probe(target=f"{base}/rl", burst=12)
    assert res["verdict"] == "rate_limited"
    assert res["ip_header_bypass"] is True


@pytest.mark.asyncio
async def test_ratelimit_probe_is_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.ratelimit_probe(target=f"{base}/rl")
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_dns_behavior_local(fresh_context):
    # 127.0.0.1 is in scope; dns_behavior resolves it (no wildcard for an IP).
    res = await srv.dns_behavior(domain="127.0.0.1")
    assert res["host"] == "127.0.0.1"
    assert "127.0.0.1" in res["a_records"]
    assert res["wildcard_dns"] is False


# -- edge_map / http_behavior / tls_behavior --------------------------------
def test_origin_hostname_hints_from_default_cert():
    from moonmcp.net import tls
    sans = ["victim.com", "*.victim.com", "www.victim.com", "origin-prod.internal.net",
            "othertenant.io", "origin-prod.internal.net"]
    hints = tls.origin_hostname_hints("victim.com", sans)
    # the target and its own sub/parent/wildcard forms are dropped; siblings/origin kept + deduped
    assert hints == ["origin-prod.internal.net", "othertenant.io"]
    assert tls.origin_hostname_hints("victim.com", ["victim.com", "*.victim.com"]) == []


def test_edge_layers_detects_cloudflare_and_cache():
    r = infra.edge_layers({"Server": "cloudflare", "CF-RAY": "abc-FRA",
                           "CF-Cache-Status": "HIT", "Via": "1.1 varnish, 1.1 cloudflare",
                           "Age": "42"})
    assert "Cloudflare" in r["vendors"]
    assert r["behind_cdn"] is True
    assert r["cache_layer"] is True
    assert len(r["proxy_hops"]) == 2


def test_summarize_http_behavior_flags_new_framing_signals():
    r = infra.summarize_http_behavior(
        baseline_status=200, connection="close", http10_status=200, invalid_method_status=501,
        oversized_status=400, bare_lf_status=400, bare_cr_status=200, obs_fold_status=200,
        dup_cl_status=200)
    assert r["bare_cr_accepted"] and r["obs_fold_accepted"] and r["dup_cl_accepted"]
    joined = " ".join(r["concerns"])
    assert "bare-CR" in joined and "obs-fold" in joined and "duplicate Content-Length" in joined
    # a rejected (4xx) framing probe is not flagged
    assert r["bare_lf_accepted"] is False


def test_summarize_http_behavior_flags_bare_lf():
    r = infra.summarize_http_behavior(baseline_status=200, connection="close",
                                      http10_status=200, invalid_method_status=501,
                                      oversized_status=None, bare_lf_status=200)
    assert r["bare_lf_accepted"] is True
    assert r["connection_header"] == "close"
    assert "keep_alive" not in r  # can't be measured from a forced-close probe
    assert any("bare-LF" in c for c in r["concerns"])


@pytest.mark.asyncio
async def test_edge_map_detects_cdn(local_server, fresh_context):
    base, _ = local_server
    res = await srv.edge_map(target=f"{base}/edge")
    assert "Cloudflare" in res["vendors"]
    assert res["behind_cdn"] is True and res["cache_layer"] is True
    assert res["concerns"]


@pytest.mark.asyncio
async def test_http_behavior_runs_against_local(local_server, fresh_context):
    base, _ = local_server
    res = await srv.http_behavior(target=base)
    assert res["baseline_status"] == 200
    # BaseHTTPRequestHandler rejects an unknown method with 501.
    assert res["invalid_method_status"] in (400, 405, 501)
    assert "bare_lf_accepted" in res


@pytest.mark.asyncio
async def test_tls_behavior_handshake_fails_gracefully_on_http(local_server, fresh_context):
    # The local server speaks plain HTTP, so a TLS handshake must fail cleanly.
    _, port = local_server
    res = await srv.tls_behavior(target=f"127.0.0.1:{port}")
    assert res["error"] == "tls_handshake_failed"
