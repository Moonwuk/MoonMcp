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


def test_valid_rejects_consecutive_dots():
    # regression: 'a..b' has an empty DNS label and must be rejected
    assert bucketsmod._valid("acme-backup")
    assert not bucketsmod._valid("ex..ample")
    assert "ex..ample" not in bucketsmod.generate_bucket_names("ex..ample")


def test_classify_status():
    assert bucketsmod.classify_status(200) == "public-listable"
    assert bucketsmod.classify_status(403) == "exists-private"
    assert bucketsmod.classify_status(302) == "exists-redirect"
    assert bucketsmod.classify_status(404) is None
    assert bucketsmod.classify_status(None) is None


def test_extract_dump_keys():
    xml = ("<ListBucketResult>"
           "<Contents><Key>backups/prod-dump.sql</Key></Contents>"
           "<Contents><Key>assets/logo.png</Key></Contents>"
           "<Contents><Key>db/mysqldump-2024.sql.gz</Key></Contents>"
           "<Contents><Key>mongodump/users.bson</Key></Contents></ListBucketResult>")
    keys = bucketsmod.extract_dump_keys(xml)
    assert set(keys) == {"backups/prod-dump.sql", "db/mysqldump-2024.sql.gz", "mongodump/users.bson"}
    # Azure <Name> form, and no false positive on ordinary assets
    assert bucketsmod.extract_dump_keys("<Blob><Name>db/full.bak</Name></Blob>") == ["db/full.bak"]
    assert bucketsmod.extract_dump_keys("<Key>css/app.css</Key><Key>img/a.png</Key>") == []


@pytest.mark.asyncio
async def test_check_buckets_flags_dump_keys():
    class _BR:
        def __init__(self, status, body):
            self.status, self.body = status, body

        def text(self, limit=None):
            return self.body.decode() if isinstance(self.body, bytes) else self.body

    class _Fake:
        async def fetch(self, url, **kwargs):
            return _BR(200, b"<ListBucketResult><Contents><Key>db/prod-dump.sql</Key>"
                           b"</Contents></ListBucketResult>")

    found = await bucketsmod.check_buckets(_Fake(), ["acme-db"], templates={"s3": "https://{name}.s3/"})
    assert found and found[0]["access"] == "public-listable"
    assert found[0]["dump_keys"] == ["db/prod-dump.sql"] and found[0]["severity"] == "critical"


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
