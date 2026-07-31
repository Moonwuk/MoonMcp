"""Integration tests — MoonMCP datastore-exposure probes against REAL services.

The unit suite exercises the probe/interpreter logic against synthetic fakes; these
validate it against ACTUAL service behaviour (a real Redis banner, a real CouchDB 3.x
welcome page, etc.). They require the services in ``docker-compose.yml`` and are
skipped unless ``MOONMCP_INTEGRATION=1`` — so they never run in the default suite/CI:

    docker compose -f tests/integration/docker-compose.yml up -d
    MOONMCP_INTEGRATION=1 pytest -m integration tests/integration -q
    docker compose -f tests/integration/docker-compose.yml down

Each test also skips (rather than fails) when its specific service isn't reachable, so
a partially-started compose still runs what it can.
"""

import os
import urllib.request

import pytest

from moonmcp.recon import datastores as ds

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("MOONMCP_INTEGRATION"),
        reason="set MOONMCP_INTEGRATION=1 and start tests/integration/docker-compose.yml",
    ),
]

HOST = os.environ.get("MOONMCP_INTEGRATION_HOST", "127.0.0.1")


async def _raw_probe(kind: str, port: int) -> dict:
    """Run a raw-TCP probe; skip (not fail) if the service isn't up."""
    res = await ds.RAW_PROBES[kind](HOST, port, 4.0)
    if res is None:
        pytest.skip(f"{kind} not reachable on {HOST}:{port}")
    return res


def _http_banner(path: str, port: int):
    """Fetch a real HTTP banner; skip if the service isn't up."""
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}{path}", timeout=4) as r:  # noqa: S310
            headers = {k.lower(): v for k, v in r.headers.items()}
            return r.status, headers, r.read(20_000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        pytest.skip(f"http://{HOST}:{port}{path} not reachable")


# ── raw-TCP probes: an unauthenticated store must read as "exposed" ─────────────
@pytest.mark.asyncio
async def test_real_redis_unauth_is_exposed():
    res = await _raw_probe("redis", 6379)
    assert res["verdict"] == "exposed", res


@pytest.mark.asyncio
async def test_real_mongodb_unauth_is_exposed():
    res = await _raw_probe("mongodb", 27017)
    assert res["verdict"] == "exposed", res


@pytest.mark.asyncio
async def test_real_memcached_unauth_is_exposed():
    res = await _raw_probe("memcached", 11211)
    assert res["verdict"] == "exposed", res


# ── HTTP interpreters against REAL banners ─────────────────────────────────────
def test_real_couchdb_banner_is_info_level():
    # CouchDB 3.x serves the root welcome banner unauthenticated even when hardened, so
    # the probe must report info-level "reachable", NOT a high "exposed" (regression for
    # the datastores fix — validated here against a real node).
    status, headers, body = _http_banner("/", 5984)
    res = ds.interpret_couchdb(status, headers, body)
    assert res is not None and res["severity"] == "info", res


def test_real_influxdb_ping_is_info_level():
    # /ping is a public health endpoint on every instance → info-level version disclosure.
    status, headers, body = _http_banner("/ping", 8086)
    res = ds.interpret_influxdb(status, headers, body)
    assert res is not None and res["severity"] == "info", res


def test_real_elasticsearch_unauth_is_exposed():
    # With security disabled the ES root genuinely returns the cluster banner unauth,
    # which IS a real exposure (interpret_es stays high).
    status, headers, body = _http_banner("/", 9200)
    res = ds.interpret_es(status, headers, body)
    assert res is not None and res["verdict"] == "exposed", res
