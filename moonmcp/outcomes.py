"""Versioned execution outcomes shared by MCP, CLI and managed dispatch.

Payloads remain compatible. MCP exposes this contract in ``_meta[RESULT_META]``;
Python callers can use ``outcome(value)`` or ``envelope(value)`` explicitly.
Detector verdicts and errors nested in observations are never execution status.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any, Literal, cast

from mcp.types import CallToolResult

from .scope import ScopeError

RESULT_META = "moonmcp.result"
OutcomeState = Literal["completed", "failed", "partial", "blocked", "cancelled", "unknown"]
_STATES = {"completed", "failed", "partial", "blocked", "cancelled", "unknown"}


@dataclass(frozen=True)
class Failure:
    code: str
    retryable: bool
    recovery: str
    message: str = ""


@dataclass(frozen=True)
class Outcome:
    state: OutcomeState = "completed"
    error: Failure | None = None

    @property
    def ok(self) -> bool:
        return self.state == "completed"

    def metadata(self) -> dict[str, Any]:
        return {"version": 1, "state": self.state, "ok": self.ok,
                "error": asdict(self.error) if self.error else None}


_RECOVERY = {
    "out_of_scope": "Check the authorised scope before choosing another action.",
    "disabled": "Check the engagement policy and configured capabilities.",
    "missing_dependency": "Install or configure the dependency, or choose an available tool.",
    "invalid_input": "Correct the arguments before retrying.",
    "not_found": "Check the identifier or choose an existing resource.",
    "budget_exhausted": "Stop this action and review the run budget.",
    "rate_limited": "Respect the reported retry delay before another attempt.",
    "timeout": "Inspect evidence for possible effects before deciding whether to retry.",
    "internal_error": "Inspect the server diagnostics before retrying.",
    "outcome_unknown": "Reconcile evidence before issuing another action; do not retry blindly.",
    "partial_result": "Review completed work and failures before scheduling remaining actions.",
    "cancelled": "Inspect completed work before scheduling another action.",
    "blocked": "Resolve the reported policy or resource constraint before continuing.",
}
_BLOCKED = {"out_of_scope", "disabled", "budget_exhausted", "missing_dependency",
            "execution_unmetered", "run_paused", "run_cancelled"}


def _failure(code: str, *, message: str = "", recovery: str = "",
             retryable: bool = False) -> Failure:
    # Legacy transports sometimes put whole exception sentences in `error`.
    # Preserve the diagnostic, but give clients a stable machine-readable code.
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code):
        message = message or code
        code = "tool_error"
    return Failure(code, retryable, recovery or _RECOVERY.get(
        code, "Inspect the error and correct its cause before retrying."), message)


class TextFailure(str):
    """An explicitly failed legacy text result, still a string for Python users.

    Mark errors at their source. Never infer status from text that may contain
    untrusted web/KB content or a successful empty search result.
    """

    error: Failure

    def __new__(cls, message: str, code: str) -> TextFailure:
        instance = super().__new__(cls, message)
        instance.error = _failure(code, message=message)
        return instance


def _from_metadata(value: object) -> Outcome | None:
    if not isinstance(value, dict) or value.get("version") != 1:
        return None
    state = value.get("state")
    if not isinstance(state, str) or state not in _STATES:
        return None
    if value.get("ok") is not (state == "completed"):
        return None
    error = value.get("error")
    if state == "completed":
        return Outcome() if error is None else None
    if not isinstance(error, dict) or not all(isinstance(error.get(k), str)
                                            for k in ("code", "recovery", "message")):
        return None
    return Outcome(cast(OutcomeState, state), _failure(error["code"], message=error["message"],
                                   recovery=error["recovery"],
                                   retryable=error.get("retryable") is True))


def outcome(result: object) -> Outcome:
    """Project execution status without interpreting vulnerability verdicts.

    `state` is an execution state only alongside an explicit boolean `ok`.
    This avoids treating a run/task/hypothesis status query as a failed call.
    `retryable` is never permission to repeat a side effect; an explicit false
    on a managed receipt overrides every legacy default.
    """
    if isinstance(result, TextFailure):
        return Outcome("blocked" if result.error.code in _BLOCKED else "failed", result.error)
    if isinstance(result, CallToolResult):
        status = _from_metadata((result.meta or {}).get(RESULT_META))
        if status is not None and result.isError == (not status.ok):
            return status
        if result.isError:
            if result.structuredContent:
                status = outcome(result.structuredContent)
                if not status.ok:
                    return status
            return Outcome("failed", _failure("tool_error"))
        # The native protocol flag is authoritative without our metadata.
        return Outcome()
    if not isinstance(result, dict):
        return Outcome()
    code = result.get("error")
    state = result.get("state") if isinstance(result.get("ok"), bool) else None
    execution_state = state if isinstance(state, str) and state in _STATES else None
    if not code and result.get("ok") is not False and execution_state in {None, "completed"}:
        return Outcome()
    if not code:
        code = {"unknown": "outcome_unknown", "partial": "partial_result",
                "blocked": "blocked", "cancelled": "cancelled"}.get(execution_state or "", "tool_error")
    detail = str(result.get("detail") or "")
    if code == "invalid_input" and detail.lower().startswith("budget exceeded:"):
        code = "budget_exhausted"
    elif result.get("available") is False and result.get("install_hint"):
        code = "missing_dependency"
    recovery = str(result.get("recovery") or result.get("hint") or result.get("install_hint") or "")
    retryable = result.get("retryable", code == "rate_limited") is True
    # Old timeout dictionaries are safe only when the producer explicitly says so.
    error = _failure(str(code), message=detail or str(code), recovery=recovery, retryable=retryable)
    if execution_state == "completed":
        execution_state = None  # conflicting payload cannot turn an error into success
    if execution_state is None:
        execution_state = ("unknown" if error.code == "outcome_unknown" else
                           "blocked" if error.code in _BLOCKED else "failed")
    return Outcome(cast(OutcomeState, execution_state), error)


def failure(result: object) -> Failure | None:
    """Compatibility projection used by CLI, benchmarks and orchestration."""
    return outcome(result).error


def envelope(result: object) -> dict[str, Any]:
    """Opt-in JSON envelope; legacy data remains intact under `data`."""
    data = result.model_dump(mode="json", by_alias=True) if isinstance(result, CallToolResult) else result
    return {**outcome(result).metadata(), "data": data}


class ToolBlocked(Exception):
    """Raised when a tool is disabled by configuration (not a scope problem)."""


def safe_tool(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Wrap a tool so scope/validation failures return structured errors."""

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await func(*args, **kwargs)
        except ScopeError as exc:
            return {"error": "out_of_scope", "detail": str(exc),
                    "hint": "Add the target to scope with scope_add, or check scope_list."}
        except ToolBlocked as exc:
            return {"error": "disabled", "detail": str(exc)}
        except TimeoutError as exc:
            return {"error": "timeout", "detail": str(exc), "retryable": False}
        except ValueError as exc:
            return {"error": getattr(exc, "code", "invalid_input"), "detail": str(exc)}
        except Exception as exc:  # never surface an opaque crash to the MCP client
            return {"error": "internal_error", "detail": f"{type(exc).__name__}: {exc}"}
    return wrapper


# Compatibility import for existing Python clients. SDK internals live in sdk.py.
from .sdk import MoonMCPFastMCP as MoonMCPFastMCP  # noqa: E402
