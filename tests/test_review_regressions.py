"""Regression tests for the confirmed findings of the adversarial detector review.

Each test pins a fix so the false-positive/logic bug can't come back.
"""

import urllib.request

import pytest

from moonmcp import server as srv
from moonmcp.recon import infra
from moonmcp.web import probes


def test_edge_layers_no_cloudfront_fp_on_plain_via():
    # A bare "via:" must NOT be read as CloudFront; Varnish in the Via value must be.
    r = infra.edge_layers({"Via": "1.1 varnish"})
    assert "CloudFront" not in r["vendors"]
    assert "Varnish" in r["vendors"]
    # Heroku's vegur likewise isn't CloudFront.
    assert "CloudFront" not in infra.edge_layers({"Via": "1.1 vegur"})["vendors"]


def test_cluster_backends_single_slow_probe_no_false_skew():
    # One backend answered, but the burst spanned 5s → not a desynced fleet.
    samples = [{"server": "nginx", "date_epoch": 100.0 + i, "elapsed_ms": 5} for i in range(6)]
    r = infra.cluster_backends(samples)
    assert r["distinct_backends"] == 1 and r["load_balanced"] is False
    assert r["patch_drift"] is False
    assert r["clock_skew_seconds"] == 0.0 and r["concerns"] == []


def test_patch_drift_ignores_bare_vs_versioned_server():
    # "nginx" vs "nginx/1.25.1" is the same product, not two versions.
    samples = [{"server": "nginx", "backend": "a", "date_epoch": 1.0, "elapsed_ms": 1},
               {"server": "nginx/1.25.1", "backend": "b", "date_epoch": 1.0, "elapsed_ms": 1}]
    assert infra.cluster_backends(samples)["patch_drift"] is False


def test_cacheable_excludes_max_age_zero():
    assert probes.cacheable({"Cache-Control": "max-age=0"})[0] is False
    assert probes.cacheable({"Cache-Control": "private, max-age=600"})[0] is False
    assert probes.cacheable({"Cache-Control": "public, max-age=60"})[0] is True


def test_ssti_findings_digit_boundary():
    # "513170" contains 51317 but is a longer digit run → not an evaluation.
    assert probes.ssti_findings("", [("Jinja2", "{{7331*7}}", "id=513170")]) == []
    # A clean evaluated result (literal payload gone) IS a finding.
    hit = probes.ssti_findings("", [("Jinja2", "{{7331*7}}", "hello 51317 world")])
    assert len(hit) == 1 and hit[0]["engine"] == "Jinja2"
    # Reflected literal payload (not evaluated) is not a finding.
    assert probes.ssti_findings("", [("Jinja2", "{{7331*7}}", "echo {{7331*7}} = 51317")]) == []


def test_ratelimit_summary_block_from_first_request_is_not_throttling():
    r = infra.ratelimit_summary([403, 403, 403], first_block=1, retry_after=None, bypass_reset=None)
    assert r["verdict"] == "endpoint_blocked"
    assert any("blanket block" in c for c in r["concerns"])


@pytest.mark.asyncio
async def test_confirm_finding_reads_selfhost_oast(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        cb = await srv.oast_generate(label="rce")
        urllib.request.urlopen(cb["http_url"], timeout=3).read()  # target "calls back"
        res = await srv.confirm_finding(target=f"{base}/echo", payload="whatever",
                                        oast_token=cb["token"])
        assert res["verdict"] == "confirmed"  # the self-host callback must be seen
        assert res["oast_interactions"]
    finally:
        await srv.oast_selfhost(action="stop")
