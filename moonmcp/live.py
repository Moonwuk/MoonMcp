"""Open a live console window that streams a long-running tool's output.

When the agent delegates to a heavy, autonomous tool (Strix), the operator wants
to *watch it work* in real time — not just read a summary afterwards. The pattern
is: tee the tool's output to a log file, then pop open a terminal window that
follows that log (``tail -f``).

This module is deliberately cross-platform and **best-effort**:

* Linux/BSD — spawn the first available terminal emulator (respecting
  ``$MOONMCP_TERMINAL`` and ``$DISPLAY``/``$WAYLAND_DISPLAY``).
* macOS — drive Terminal.app via ``osascript``.
* Windows — a follow window via PowerShell (``Get-Content -Wait``).
* Headless (no GUI) — fall back to a detached ``tmux`` session the operator can
  ``tmux attach`` to, and finally to a copy-pasteable ``tail -f`` hint.

It **never blocks** the caller (the terminal is fire-and-forget) and **never
raises** into the caller — watching is a convenience and must not break a run.
All paths that reach a shell are quoted with :func:`shlex.quote`, so a log path
containing spaces or shell metacharacters can't break out of the follow command.
"""

from __future__ import annotations

import os
import platform
import re
import shlex
import shutil
import subprocess

# Linux/BSD terminal launchers, in preference order (Debian/Kali's
# ``x-terminal-emulator`` alternative first, then common desktops). Each entry is
# ``(executable, args_before_command, mode)``:
#   * "argv"   — append ``bash -c <cmd>`` as SEPARATE argv elements (the terminal
#                does not re-parse them, so nothing can be re-split/injected).
#   * "string" — the terminal wants the command as ONE string it parses itself;
#                we hand it ``bash -c <shell-quoted cmd>``.
_LINUX_LAUNCHERS: list[tuple[str, list[str], str]] = [
    ("x-terminal-emulator", ["-e"], "argv"),
    ("qterminal", ["-e"], "argv"),
    ("gnome-terminal", ["--"], "argv"),
    ("konsole", ["-e"], "argv"),
    ("xfce4-terminal", ["--command"], "string"),
    ("mate-terminal", ["--"], "argv"),
    ("tilix", ["-e"], "argv"),
    ("kitty", [], "argv"),
    ("alacritty", ["-e"], "argv"),
    ("wezterm", ["start", "--"], "argv"),
    ("foot", [], "argv"),
    ("xterm", ["-e"], "argv"),
    ("urxvt", ["-e"], "argv"),
    ("st", ["-e"], "argv"),
]


def follow_command(log_path: str | os.PathLike[str], *, title: str = "live") -> str:
    """A POSIX-shell command string that follows *log_path* and keeps the window
    open after the stream ends (so the operator can read the final output)."""

    q = shlex.quote(str(log_path))
    banner = shlex.quote(f"== {title} : live output (close this window to stop watching) ==")
    return (
        f"printf '%s\\n\\n' {banner}; "
        f"tail -n +1 -f {q} 2>/dev/null || true; "
        f"printf '\\n[stream ended - press Enter to close]'; read _"
    )


def _linux_argv(exe: str, flag_args: list[str], mode: str, command: str) -> list[str]:
    """Build the terminal argv for *command* under the given launcher mode."""

    if mode == "string":
        return [exe, *flag_args, f"bash -c {shlex.quote(command)}"]
    return [exe, *flag_args, "bash", "-c", command]


def _has_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _linux_terminal_argv(command: str) -> list[str] | None:
    """Pick a Linux terminal for *command*, honouring ``$MOONMCP_TERMINAL``.

    Returns ``None`` when there is no usable GUI terminal (no display, or none of
    the known emulators are installed) so the caller can fall back to tmux.
    """

    if not _has_display():
        return None
    override = os.environ.get("MOONMCP_TERMINAL", "").strip()
    if override:
        usable = bool(shutil.which(override)) or (
            os.path.isabs(override) and os.access(override, os.X_OK))
        if usable:
            # Keep the operator's name as argv[0] (PATH resolves it at spawn).
            flag = os.environ.get("MOONMCP_TERMINAL_EXEC", "-e").strip()
            flag_args = [flag] if flag else []
            return _linux_argv(override, flag_args, "argv", command)
    for exe, flag_args, mode in _LINUX_LAUNCHERS:
        if shutil.which(exe):
            return _linux_argv(exe, flag_args, mode, command)
    return None


def _applescript_escape(s: str) -> str:
    """Escape a string for embedding inside an AppleScript double-quoted literal."""

    return s.replace("\\", "\\\\").replace('"', '\\"')


def _macos_argv(command: str) -> list[str]:
    """Drive Terminal.app to run *command* in a new window via ``osascript``."""

    script = f'tell application "Terminal" to do script "{_applescript_escape(command)}"'
    activate = 'tell application "Terminal" to activate'
    return ["osascript", "-e", script, "-e", activate]


def _windows_argv(log_path: str) -> list[str]:
    """A PowerShell follow window for *log_path* (best-effort, Windows only)."""

    ps_path = str(log_path).replace("'", "''")  # single-quote escaping for PowerShell
    follow = f"Get-Content -Wait -Tail 1000 -Path '{ps_path}'"
    if shutil.which("wt"):  # Windows Terminal, if present
        return ["wt", "powershell", "-NoExit", "-Command", follow]
    return ["cmd", "/c", "start", "powershell", "-NoExit", "-Command", follow]


def _safe_session_name(title: str) -> str:
    """A tmux-safe session name (no ``.``/``:``/whitespace) derived from *title*."""

    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", title).strip("-").lower() or "watch"
    return f"strix-{slug}"[:60]


def _try_tmux(command: str, title: str) -> dict | None:
    """Fallback for headless boxes: stream *command* into a detached tmux session
    the operator can attach to. Returns a result dict, or ``None`` if tmux is
    unavailable or the session couldn't be created."""

    tmux = shutil.which("tmux")
    if not tmux:
        return None
    session = _safe_session_name(title)
    try:
        subprocess.run([tmux, "kill-session", "-t", session],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, check=False)
        subprocess.run([tmux, "new-session", "-d", "-s", session, command],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return {
        "opened": True,
        "method": "tmux",
        "session": session,
        "attach_hint": f"tmux attach -t {session}",
        "detail": (f"no GUI terminal available - streaming into detached tmux session "
                   f"'{session}'. Attach with: tmux attach -t {session}"),
    }


def _fallback(log_path: str | None, reason: str) -> dict:
    """No window could be opened — hand back a copy-pasteable follow hint."""

    hint = f"tail -n +1 -f {shlex.quote(log_path)}" if log_path else None
    return {
        "opened": False,
        "method": "none",
        "reason": reason,
        "attach_hint": hint,
        "detail": (f"could not open a live console ({reason})."
                   + (f" Watch it yourself with: {hint}" if hint else "")),
    }


def _spawn(argv: list[str]) -> subprocess.Popen:
    """Fire-and-forget spawn of a terminal, fully detached from this process."""

    return subprocess.Popen(  # noqa: S603 - argv is built from a fixed launcher table
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def open_console(command: str, *, title: str = "live", log_path: str | None = None) -> dict:
    """Open a terminal window running the shell *command*. Non-blocking; never raises.

    Returns a dict: ``{opened, method, ...}``. On success ``opened`` is True and
    ``method`` names how (a terminal executable, or ``"tmux"``); on failure
    ``opened`` is False and ``attach_hint`` carries a ``tail -f`` the operator can
    run by hand. *log_path* is used only to build that hint.
    """

    system = platform.system()
    try:
        if system == "Darwin":
            argv: list[str] | None = _macos_argv(command)
        elif system == "Windows":
            argv = _windows_argv(log_path) if log_path else None
        else:  # Linux / other POSIX
            argv = _linux_terminal_argv(command)
            if argv is None:
                tmux = _try_tmux(command, title)
                if tmux is not None:
                    tmux["log"] = log_path
                    return tmux
                return _fallback(log_path, "no GUI terminal and no tmux")
        if argv is None:
            return _fallback(log_path, f"no console strategy for {system}")
        proc = _spawn(argv)
    except (OSError, subprocess.SubprocessError) as exc:
        # A missing/renamed terminal binary etc. — try tmux, then a hint.
        if system not in ("Darwin", "Windows"):
            tmux = _try_tmux(command, title)
            if tmux is not None:
                tmux["log"] = log_path
                return tmux
        return _fallback(log_path, f"{type(exc).__name__}: {exc}")
    return {
        "opened": True,
        "method": argv[0],
        "pid": proc.pid,
        "log": log_path,
        "argv": argv,
        "attach_hint": (f"tail -n +1 -f {shlex.quote(log_path)}" if log_path else None),
        "detail": f"live console opened via {argv[0]}",
    }


def open_log_console(log_path: str | os.PathLike[str], *, title: str = "live") -> dict:
    """Convenience: open a live console that follows *log_path*."""

    cmd = follow_command(log_path, title=title)
    return open_console(cmd, title=title, log_path=str(log_path))


def probe() -> dict:
    """Report — without spawning anything — how a live console *would* be opened
    here. Handy for a readiness check (e.g. Strix's ``strix_available``)."""

    system = platform.system()
    if system == "Darwin":
        return {"available": shutil.which("osascript") is not None,
                "method": "osascript", "system": system}
    if system == "Windows":
        return {"available": True,
                "method": "wt" if shutil.which("wt") else "powershell", "system": system}
    override = os.environ.get("MOONMCP_TERMINAL", "").strip()
    if _has_display():
        if override and shutil.which(override):
            return {"available": True, "method": override, "system": system,
                    "display": True}
        for exe, _flag, _mode in _LINUX_LAUNCHERS:
            if shutil.which(exe):
                return {"available": True, "method": exe, "system": system,
                        "display": True}
    if shutil.which("tmux"):
        return {"available": True, "method": "tmux", "system": system,
                "display": _has_display(),
                "note": "no GUI terminal; will use a detached tmux session"}
    return {"available": False, "method": None, "system": system,
            "display": _has_display(),
            "note": "no GUI terminal and no tmux; falls back to a tail -f hint"}
