"""Strix-as-an-MCP-tool — a thin, scope-gated wrapper.

Exposes the open-source **Strix** autonomous pentester (https://github.com/usestrix/strix,
Apache-2.0) as ordinary MCP tools, so the SAME agent that already speaks to
MoonMCP (opencode / hermes / Claude) can delegate deep, PoC-generating validation
to Strix without a separate window.

It deliberately reuses two things from MoonMCP so Strix inherits the same
discipline:

* ``moonmcp.scope.ScopeManager`` — the target is scope-checked *before* Strix is
  ever launched (Strix exploits; it must never be pointed off-scope), and
* ``moonmcp.prompts.RULES_OF_ENGAGEMENT`` — prepended to every instruction so
  Strix operates under the same authorised-testing rules.

Strix runs headlessly as::

    strix -n --target <url|repo|./path> --instruction-file <file>

with ``STRIX_LLM`` + ``LLM_API_KEY`` set and Docker running; results land in
``strix_runs/<run-name>``. This wrapper is a REFERENCE integration — adapt the
result-parsing to your Strix version. Authorised testing only.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

try:  # reuse MoonMCP's guard + prompt base when installed alongside
    from moonmcp.prompts import RULES_OF_ENGAGEMENT
    from moonmcp.scope import ScopeError, ScopeManager
except Exception:  # pragma: no cover - allow standalone use
    RULES_OF_ENGAGEMENT = "RULES OF ENGAGEMENT: authorised, in-scope targets only; no destructive actions.\n"
    ScopeManager = None  # type: ignore[assignment,misc]

    class ScopeError(Exception):  # type: ignore[no-redef]
        pass

try:  # the live-console opener (lets the operator watch Strix in a real window)
    from moonmcp import live as _live
except Exception:  # pragma: no cover - watching is optional
    _live = None  # type: ignore[assignment]


RUNS_DIR = Path(os.environ.get("STRIX_RUNS_DIR", "strix_runs"))
mcp = FastMCP("strix", instructions=(
    "Strix delegated-validation tools. Use MoonMCP for cheap recon/detection first; "
    "delegate only high-value, in-scope leads here for PoC validation. Targets are "
    "scope-checked before Strix runs. Authorised testing only."
))


def _build_scope() -> ScopeManager | None:
    if ScopeManager is None:
        return None
    raw = os.environ.get("STRIX_SCOPE") or os.environ.get("MOONMCP_SCOPE") or ""
    entries = [e.strip() for e in raw.replace("\n", ",").split(",") if e.strip()]
    enforce = os.environ.get("STRIX_ENFORCE_SCOPE", "1").strip().lower() in {"1", "true", "yes", "on"}
    scope = ScopeManager(enforce=enforce, block_private=True)
    for e in entries:
        scope.add(e)
    return scope


def _scope_check(target: str) -> str | None:
    """Return an error string if *target* is a network host out of scope, else None."""

    t = target.strip()
    # Code targets (a local path or a git repo) are not network hosts; the operator
    # authorises those out of band. Only gate URL/host targets here.
    if t.startswith(("./", "/", "~")) or t.endswith(".git") or t.startswith("git@"):
        return None
    scope = _build_scope()
    if scope is None:
        return None
    if scope.is_empty and scope.enforce:
        return ("no scope configured — set STRIX_SCOPE (or MOONMCP_SCOPE) to the "
                "authorised targets before delegating to Strix")
    try:
        scope.check(t)
    except ScopeError as exc:
        return str(exc)
    return None


@mcp.tool()
async def strix_available() -> dict:
    """Report whether Strix can run here: the `strix` binary on PATH, Docker
    reachable, and the LLM env (`STRIX_LLM` + `LLM_API_KEY`) configured."""

    strix_path = shutil.which("strix")
    docker = shutil.which("docker")
    docker_ok = False
    if docker:
        try:
            proc = await asyncio.create_subprocess_exec(
                docker, "info", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            docker_ok = (await asyncio.wait_for(proc.wait(), timeout=10)) == 0
        except Exception:
            docker_ok = False
    return {
        "strix_installed": strix_path is not None,
        "strix_path": strix_path,
        "docker_running": docker_ok,
        "llm_configured": bool(os.environ.get("STRIX_LLM") and os.environ.get("LLM_API_KEY")),
        "llm_model": os.environ.get("STRIX_LLM"),
        "scope": (_build_scope().entries() if _build_scope() else None),
        # How a live "watch Strix work" console would open here (set MOONMCP_TERMINAL
        # to force a specific emulator; falls back to tmux, then a tail -f hint).
        "live_console": (_live.probe() if _live is not None
                         else {"available": False, "reason": "moonmcp.live unavailable"}),
        "ready": bool(strix_path and docker_ok and os.environ.get("LLM_API_KEY")),
    }


def _compose_instruction(instruction: str) -> str:
    """Prepend the shared rules of engagement to the operator's instruction."""

    return (
        f"{RULES_OF_ENGAGEMENT}\n"
        "OBJECTIVE: validate the lead(s) below with a MINIMAL, non-destructive "
        "proof-of-concept and STOP at proof. Report reproduction steps + impact. "
        "A finding is 'confirmed' only with a reproducible PoC; otherwise say so.\n\n"
        f"{instruction.strip()}\n"
    )


async def _latest_run() -> Path | None:
    if not RUNS_DIR.exists():
        return None
    runs = [p for p in RUNS_DIR.iterdir() if p.is_dir()]
    return max(runs, key=lambda p: p.stat().st_mtime) if runs else None


def _collect_run(run_dir: Path) -> dict:
    """Best-effort read of a Strix run directory (adapt to your Strix version)."""

    files = [str(p.relative_to(run_dir)) for p in run_dir.rglob("*") if p.is_file()]
    reports: dict[str, str] = {}
    for p in run_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".md", ".json"} and p.stat().st_size < 200_000:
            try:
                reports[str(p.relative_to(run_dir))] = p.read_text(errors="replace")[:20000]
            except OSError:
                pass
    return {"run_dir": str(run_dir), "files": files[:200], "reports": reports}


def _watch_title(target: str) -> str:
    """A short, human-readable title for the live-console window / tmux session."""

    return f"strix {target}"[:60]


def _open_watch_log() -> tuple[str, object] | tuple[None, None]:
    """Create a fresh live-output log under RUNS_DIR and open it for writing.

    Returns ``(path, file_handle)`` so Strix's stdout/stderr can be teed into it
    while a console follows it, or ``(None, None)`` if it couldn't be created (in
    which case watching is skipped and the run proceeds normally)."""

    try:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        path = str(RUNS_DIR / f"strix-live-{os.getpid()}-{int(time.time())}.log")
        return path, open(path, "wb")
    except OSError:
        return None, None


def _read_log_tail(path: str, limit: int = 8000) -> str:
    """Read the last *limit* bytes of the live log (what the console showed)."""

    try:
        with open(path, "rb") as fh:
            try:
                fh.seek(-limit, os.SEEK_END)
            except OSError:
                fh.seek(0)
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


async def _kill_quietly(proc: asyncio.subprocess.Process) -> None:
    try:
        proc.kill()
        await proc.wait()
    except (ProcessLookupError, OSError):
        pass


@mcp.tool()
async def strix_run(target: str, instruction: str, wait: bool = True,
                    timeout: int = 1800, extra_args: list[str] | None = None,
                    watch: bool = True) -> dict:
    """Delegate a focused, in-scope validation task to Strix (autonomous PoC).

    `target` is a URL / host (scope-checked) or a code target (repo URL / local
    path). `instruction` should be a tight, evidence-backed task — the shared
    rules of engagement are prepended automatically. With `wait` (default), runs
    to completion (bounded by `timeout` seconds) and returns the parsed run;
    otherwise launches it detached and returns the run dir to poll with
    `strix_result`. Requires `strix` + Docker + LLM env (see `strix_available`).

    `watch` (default on) tees Strix's live output to a log under `strix_runs/` and
    pops open a terminal window that follows it, so you can watch Strix work in
    real time. It degrades gracefully (tmux session, else a `tail -f` hint) when
    no GUI terminal is available, and never blocks the run. Set `watch=False`, or
    `MOONMCP_TERMINAL` to force a specific emulator.
    """

    err = _scope_check(target)
    if err is not None:
        return {"error": "out_of_scope", "detail": err}
    if shutil.which("strix") is None:
        return {"error": "strix_unavailable",
                "detail": "strix is not installed. See https://github.com/usestrix/strix"}
    if not os.environ.get("LLM_API_KEY"):
        return {"error": "llm_unconfigured", "detail": "set STRIX_LLM and LLM_API_KEY"}

    tmp = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, prefix="strix-instr-")
    tmp.write(_compose_instruction(instruction))
    tmp.close()
    args = ["strix", "-n", "--target", target, "--instruction-file", tmp.name, *(extra_args or [])]

    # When watching, Strix's output goes to a log file the live console follows;
    # otherwise keep the original PIPE/DEVNULL behaviour.
    log_path, logf = _open_watch_log() if (watch and _live is not None) else (None, None)
    console: dict | None = None

    if not wait:
        # Detached: the agent polls strix_result() for the run when it lands.
        if logf is not None:
            await asyncio.create_subprocess_exec(
                *args, stdout=logf, stderr=asyncio.subprocess.STDOUT)
            logf.close()  # the child inherited its own copy of the fd
            console = _live.open_log_console(log_path, title=_watch_title(target))
        else:
            await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        result = {"launched": True, "target": target, "command": args,
                  "note": "running in background; poll with strix_result()"}
        if console is not None:
            result["live_console"], result["log"] = console, log_path
        return result

    if logf is not None:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=logf, stderr=asyncio.subprocess.STDOUT)
        logf.close()  # the child inherited its own copy of the fd
        console = _live.open_log_console(log_path, title=_watch_title(target))
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            await _kill_quietly(proc)
            return {"error": "timeout", "detail": f"strix exceeded {timeout}s",
                    "target": target, "live_console": console, "log": log_path}
        finally:
            _unlink_quietly(tmp.name)
        stdout = _read_log_tail(log_path)
    else:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            await _kill_quietly(proc)
            return {"error": "timeout", "detail": f"strix exceeded {timeout}s", "target": target}
        finally:
            _unlink_quietly(tmp.name)
        stdout = out_b.decode("utf-8", "replace")

    run = await _latest_run()
    result = {
        "target": target,
        # Strix exits non-zero when it FINDS vulnerabilities — that is a signal.
        "exit_code": proc.returncode,
        "vulnerabilities_found": proc.returncode not in (0, None),
        "stdout_tail": stdout[-8000:],
    }
    if console is not None:
        result["live_console"], result["log"] = console, log_path
    if run is not None:
        result.update(_collect_run(run))
    return result


@mcp.tool()
async def strix_result(run_name: str | None = None) -> dict:
    """Read a Strix run directory under `strix_runs/` — the named one, or the most
    recent when omitted. Returns the file list and any Markdown/JSON reports."""

    run = (RUNS_DIR / run_name) if run_name else await _latest_run()
    if run is None or not run.exists():
        return {"error": "not_found", "detail": f"no Strix run at {run}"}
    return _collect_run(run)


if __name__ == "__main__":
    mcp.run()
