"""The live-console opener (moonmcp.live).

These tests never open a real window: the process spawn, ``shutil.which`` and
``platform.system`` are all monkeypatched, so we assert on the *command that
would be run* and on graceful degradation — including that a hostile log path
can't break out of the follow command.
"""

import shlex
import types

import pytest

from moonmcp import live


def _fake_which(*present):
    names = set(present)
    return lambda exe: (f"/usr/bin/{exe}" if exe in names else None)


class _FakeProc:
    def __init__(self, argv):
        self.argv = argv
        self.pid = 4242


@pytest.fixture
def capture_spawn(monkeypatch):
    """Replace the real spawn with a recorder; return the list it appends to."""

    calls: list[list[str]] = []

    def fake_spawn(argv):
        calls.append(argv)
        return _FakeProc(argv)

    monkeypatch.setattr(live, "_spawn", fake_spawn)
    return calls


# -- follow_command / quoting ------------------------------------------------
def test_follow_command_quotes_path_and_follows():
    cmd = live.follow_command("/var/log/strix.log", title="run-1")
    assert "tail -n +1 -f" in cmd
    assert shlex.quote("/var/log/strix.log") in cmd
    assert "read _" in cmd  # keeps the window open after the stream ends


def test_follow_command_is_injection_safe():
    # A path with a space AND a shell metacharacter must survive as ONE token.
    evil = "/tmp/a b; rm -rf ~ #.log"
    cmd = live.follow_command(evil, title="x")
    # shlex round-trips the quoted path back to exactly one intact token.
    assert evil in shlex.split(cmd)


def test_linux_argv_argv_mode_keeps_command_as_separate_arg():
    argv = live._linux_argv("gnome-terminal", ["--"], "argv", "tail -f /x")
    assert argv == ["gnome-terminal", "--", "bash", "-c", "tail -f /x"]


def test_linux_argv_string_mode_quotes_whole_command():
    argv = live._linux_argv("xfce4-terminal", ["--command"], "string", "tail -f /x")
    assert argv == ["xfce4-terminal", "--command", "bash -c 'tail -f /x'"]


# -- Linux terminal selection ------------------------------------------------
def test_linux_terminal_prefers_first_available(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("MOONMCP_TERMINAL", raising=False)
    monkeypatch.setattr(live.shutil, "which", _fake_which("xterm"))
    argv = live._linux_terminal_argv("CMD")
    assert argv is not None and argv[0] == "xterm"


def test_linux_terminal_honours_override(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setenv("MOONMCP_TERMINAL", "kitty")
    monkeypatch.setattr(live.shutil, "which", _fake_which("kitty", "xterm"))
    argv = live._linux_terminal_argv("CMD")
    assert argv is not None and argv[0] == "kitty"
    assert argv[-3:] == ["bash", "-c", "CMD"]


def test_linux_terminal_none_without_display(monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(live.shutil, "which", _fake_which("xterm"))
    assert live._linux_terminal_argv("CMD") is None


# -- open_console: happy path + degradation ----------------------------------
def test_open_console_linux_spawns_terminal(monkeypatch, capture_spawn):
    monkeypatch.setattr(live.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("MOONMCP_TERMINAL", raising=False)
    monkeypatch.setattr(live.shutil, "which", _fake_which("gnome-terminal"))
    res = live.open_console("tail -f /x", title="t", log_path="/x")
    assert res["opened"] is True
    assert res["method"] == "gnome-terminal"
    assert res["pid"] == 4242
    assert capture_spawn and capture_spawn[0][0] == "gnome-terminal"


def test_open_console_falls_back_to_tmux(monkeypatch):
    monkeypatch.setattr(live.platform, "system", lambda: "Linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(live.shutil, "which", _fake_which("tmux"))
    ran: list[list[str]] = []

    def fake_run(argv, **kw):
        ran.append(argv)
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    res = live.open_console("tail -f /x", title="run 1/2", log_path="/x")
    assert res["opened"] is True and res["method"] == "tmux"
    # session name is tmux-safe (no spaces/slashes/colons)
    assert res["session"] == "strix-run-1-2"
    assert res["attach_hint"] == "tmux attach -t strix-run-1-2"
    # a new-session command was actually issued
    assert any("new-session" in a for a in ran)


def test_open_console_hint_when_no_terminal_no_tmux(monkeypatch):
    monkeypatch.setattr(live.platform, "system", lambda: "Linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(live.shutil, "which", _fake_which())  # nothing installed
    res = live.open_console("tail -f /x", title="t", log_path="/var/log/x.log")
    assert res["opened"] is False and res["method"] == "none"
    assert res["attach_hint"] == f"tail -n +1 -f {shlex.quote('/var/log/x.log')}"


def test_open_console_never_raises_on_spawn_error(monkeypatch):
    monkeypatch.setattr(live.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(live.shutil, "which", _fake_which("xterm"))  # no tmux

    def boom(argv):
        raise OSError("no such binary")

    monkeypatch.setattr(live, "_spawn", boom)
    res = live.open_console("tail -f /x", title="t", log_path="/x")
    assert res["opened"] is False  # degraded, not crashed
    assert "attach_hint" in res


def test_open_console_macos_uses_osascript(monkeypatch, capture_spawn):
    monkeypatch.setattr(live.platform, "system", lambda: "Darwin")
    res = live.open_console('tail -f /x', title="t", log_path="/x")
    assert res["opened"] is True and res["method"] == "osascript"
    argv = capture_spawn[0]
    assert argv[0] == "osascript"
    assert any("Terminal" in part for part in argv)


def test_macos_argv_escapes_applescript_quotes():
    argv = live._macos_argv('say "hi" \\ bye')
    # embedded quotes/backslashes are escaped for the AppleScript literal
    assert '\\"hi\\"' in argv[2]
    assert "\\\\" in argv[2]


# -- open_log_console + probe ------------------------------------------------
def test_open_log_console_builds_follow(monkeypatch, capture_spawn):
    monkeypatch.setattr(live.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("MOONMCP_TERMINAL", raising=False)
    monkeypatch.setattr(live.shutil, "which", _fake_which("konsole"))
    res = live.open_log_console("/tmp/run.log", title="t")
    assert res["opened"] is True
    inner = capture_spawn[0][-1]  # the bash -c command
    assert "tail -n +1 -f" in inner and shlex.quote("/tmp/run.log") in inner


def test_safe_session_name_sanitises():
    assert live._safe_session_name("strix https://a.b/c?d=1") == "strix-strix-https-a-b-c-d-1"
    assert live._safe_session_name("") == "strix-watch"


def test_probe_returns_a_method(monkeypatch):
    monkeypatch.setattr(live.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("MOONMCP_TERMINAL", raising=False)
    monkeypatch.setattr(live.shutil, "which", _fake_which("gnome-terminal"))
    p = live.probe()
    assert p["available"] is True and p["method"] == "gnome-terminal"
