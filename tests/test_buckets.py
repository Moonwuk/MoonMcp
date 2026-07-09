"""Tests for cloud bucket enumeration."""

import pytest

from moonmcp import server as srv
from moonmcp.recon import buckets as bucketsmod


def test_generate_bucket_names():
    names = bucketsmod.generate_bucket_names("acme.com")
    assert "acme" in names                 # registrable label
    assert "acme-backup" in names
    assert "acme-dev" in names
    assert "prod-acme" in names
    # all DNS-valid, unique
    assert len(names) == len(set(names))
    assert all(3 <= len(n) <= 63 for n in names)


def test_classify_status():
    assert bucketsmod.classify_status(200) == "public-listable"
    assert bucketsmod.classify_status(403) == "exists-private"
    assert bucketsmod.classify_status(302) == "exists-redirect"
    assert bucketsmod.classify_status(404) is None
    assert bucketsmod.classify_status(None) is None


@pytest.mark.asyncio
async def test_check_buckets_against_mock(local_server, fresh_context):
    base, _ = local_server
    ctx = fresh_context
    templates = {"mock": base + "/bucket?name={name}"}
    found = await bucketsmod.check_buckets(
        ctx.http, ["acme-backup", "acme-private", "acme-nope"], templates=templates)
    by_name = {f["name"]: f for f in found}
    assert by_name["acme-backup"]["access"] == "public-listable"
    assert by_name["acme-private"]["access"] == "exists-private"
    assert "acme-nope" not in by_name           # 404 → absent
    # public buckets rank first
    assert found[0]["access"] == "public-listable"


@pytest.mark.asyncio
async def test_cloud_buckets_tool_structure(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "cloud_buckets" in tools
    # real providers are unreachable in the sandbox → still returns clean structure
    out = await srv.cloud_buckets(keyword="acme", max_candidates=5)
    assert out["candidates_tested"] >= 1
    assert "s3" in out["providers"] and isinstance(out["found"], list)
