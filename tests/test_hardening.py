"""Tests for the roadmap hardening fixes: run_scanner file-I/O guard, live JWT
expiry check, and the safe_tool catch-all."""

import base64
import json

import pytest

from moonmcp import server as srv


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_reject_dangerous_scanner_args():
    r = srv._reject_dangerous_scanner_args
    assert r(["-u", "https://example.com"]) is None
    assert r(["-silent", "-jsonl"]) is None
    assert r(["-o", "/etc/cron.d/evil"]) is not None          # output flag
    assert r(["-config=/tmp/x"]) is not None                   # config flag (=form)
    assert r(["-u", "https://x", "../../etc/passwd"]) is not None  # traversal
    assert r(["/etc/passwd"]) is not None                      # absolute path
    assert r(["-w", "wordlist.txt"]) is not None               # file-read flag


@pytest.mark.asyncio
async def test_run_scanner_blocks_file_io(monkeypatch):
    ctx = srv.build_context()
    ctx.scope.add("example.com")
    monkeypatch.setattr(srv, "_CTX", ctx)
    out = await srv.run_scanner(tool="nuclei", args=["-u", "https://example.com", "-o", "/tmp/out"])
    assert out.get("error") == "unsafe_args"


@pytest.mark.asyncio
async def test_jwt_expiry_is_flagged():
    # exp far in the past → must be reported as EXPIRED now that now_epoch is wired
    token = f"{_b64({'alg': 'HS256'})}.{_b64({'sub': 'x', 'exp': 100})}.sig"
    res = await srv.jwt_analyze(token=token)
    issues = " ".join(res.get("issues", [])).lower()
    assert "expired" in issues, res


@pytest.mark.asyncio
async def test_safe_tool_catches_unexpected(monkeypatch):
    # force an unexpected error inside a wrapped tool → structured, not a crash
    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(srv.cli, "detect_tools", boom)
    res = await srv.server_status()
    assert res.get("error") == "internal_error"
    assert "kaboom" in res.get("detail", "")
