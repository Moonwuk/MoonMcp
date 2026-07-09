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
