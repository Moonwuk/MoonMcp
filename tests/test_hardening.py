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


def test_env_bool_empty_string_falls_back_to_default(monkeypatch):
    from moonmcp import config as cfgmod
    # a blank value (what MCP env blocks / shell wrappers emit for an "unset" var)
    # must NOT disable a safety flag — only explicit 0/false/off/… do.
    monkeypatch.setenv("MOONMCP_TESTFLAG", "")
    assert cfgmod._env_bool("MOONMCP_TESTFLAG", True) is True
    assert cfgmod._env_bool("MOONMCP_TESTFLAG", False) is False
    monkeypatch.setenv("MOONMCP_TESTFLAG", "   ")           # whitespace-only == blank
    assert cfgmod._env_bool("MOONMCP_TESTFLAG", True) is True
    monkeypatch.setenv("MOONMCP_TESTFLAG", "0")             # explicit disable still works
    assert cfgmod._env_bool("MOONMCP_TESTFLAG", True) is False


def test_host_like_tokens_catches_obfuscated_ips_not_status_codes():
    tk = srv._host_like_tokens
    got = tk(["scanme.example.com", "2852039166", "0x7f000001", "127.1", "::1"])
    for t in ("2852039166", "0x7f000001", "127.1", "::1"):
        assert t in got, t
    # benign scanner values (status codes / ports / counts) must NOT look like targets
    assert tk(["-mc", "200,301,404", "-rl", "150"]) == []


@pytest.mark.asyncio
async def test_run_scanner_refuses_smuggled_obfuscated_ip(monkeypatch):
    # The smuggling exploit: one in-scope token satisfies the no_target guard while an
    # obfuscated internal IP (2852039166 == 169.254.169.254) rides along in args. It
    # must be scope-checked and refused, not passed to the scanner unchecked.
    import dataclasses as _dc
    ctx = srv.build_context()
    ctx.scope.add("example.com")
    ctx.settings = _dc.replace(ctx.settings, allow_intrusive=True)
    monkeypatch.setattr(srv, "_CTX", ctx)
    out = await srv.run_scanner(tool="nmap", args=["scanme.example.com", "2852039166"])
    assert out.get("error") == "out_of_scope", out


@pytest.mark.asyncio
async def test_run_scanner_blocks_file_io(monkeypatch):
    import dataclasses as _dc
    ctx = srv.build_context()
    ctx.scope.add("example.com")
    # run_scanner is intrusive-gated; dataclass defaults to False now. The test
    # is about unsafe-arg rejection, which happens BEFORE the intrusive gate —
    # but the gate fires first, so enable it to reach the arg validator.
    ctx.settings = _dc.replace(ctx.settings, allow_intrusive=True)
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
