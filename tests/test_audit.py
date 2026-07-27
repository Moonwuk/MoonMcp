"""Tests for logging setup and the audit log."""

import json
import logging
import sys

import pytest

from moonmcp import server as srv
from moonmcp.audit import AuditLog, setup_logging


def test_logger_writes_to_stderr_not_stdout():
    logger = setup_logging()
    # the stdio MCP transport owns stdout — the handler MUST target stderr
    streams = [h.stream for h in logger.handlers if isinstance(h, logging.StreamHandler)]
    assert streams and all(s is sys.stderr for s in streams)
    assert logger.propagate is False


def test_audit_log_records_and_persists(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    a = AuditLog(path=path, cap=3)
    a.record("scope_check", tool="http_probe", target="a.example.com", decision="allow")
    a.record("scope_check", tool="port_scan", target="b.example.com", decision="deny")
    assert a.recent()[-1]["decision"] == "deny"
    assert a.summary()["total"] == 2
    # ring buffer cap
    for i in range(5):
        a.record("x", tool=str(i))
    assert len(a.recent(1000)) == 3
    # JSONL persisted, one valid object per line
    lines = [json.loads(x) for x in open(path).read().splitlines()]
    assert len(lines) == 7 and all("ts" in ln and "event" in ln for ln in lines)


@pytest.mark.asyncio
async def test_scope_decisions_are_audited(local_server, fresh_context):
    base, _ = local_server
    ctx = fresh_context
    await srv.http_probe(target=base)                 # in scope → allow
    await srv.http_probe(target="http://evil.example.test/")  # out of scope → deny
    events = ctx.audit.recent(50)
    decisions = {(e.get("decision")) for e in events if e["event"] == "scope_check"}
    assert "allow" in decisions and "deny" in decisions
    # the audit tool surfaces it
    out = await srv.audit_log(event="scope_check")
    assert out["count"] >= 2


@pytest.mark.asyncio
async def test_audit_resource_registered():
    resources = {str(r.uri) for r in await srv.mcp.list_resources()}
    assert any(u.startswith("audit://") for u in resources)
    assert "audit_log" in {t.name for t in await srv.mcp.list_tools()}
