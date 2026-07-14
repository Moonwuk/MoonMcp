"""Structured, self-correcting error envelopes for tool results.

A tool failure is a teaching moment: instead of a bare `{"error": ...}` that
stalls the agent, every common failure carries an ``action`` — a one-line, next
concrete step the agent (or operator) can take to recover. Scope denials say how
to add the target; an unconfigured OAST says which tool to start; a not-found says
to list what exists first. This turns a dead end into a self-correcting step.

Purely additive: the ``error`` code is unchanged (callers and tests that switch on
it keep working); ``action`` and ``detail`` are extra keys.
"""

from __future__ import annotations

# error code -> the concrete next step that recovers from it.
DEFAULT_ACTIONS: dict[str, str] = {
    "out_of_scope": "add the host to scope with scope_add (or activate its program), "
                    "or pick an in-scope target",
    "disabled": "intrusive tools are off — set MOONMCP_ALLOW_INTRUSIVE=1 once you've "
                "confirmed you're authorised for this target, then retry",
    "intrusive_disabled": "set MOONMCP_ALLOW_INTRUSIVE=1 (only when authorised), then retry",
    "oast_unconfigured": "start the built-in catcher with oast_selfhost (or point at a "
                         "collaborator with oast_configure), then retry",
    "not_found": "check the id/name — list what exists first (e.g. tool_catalog, "
                 "list_findings, program_list, memory_graph)",
    "unreachable": "the host didn't respond — verify it's up, correctly spelled, and in scope",
    "invalid_token": "the input isn't a valid token/JWT — re-copy the whole value including "
                     "all three dot-separated segments",
    "invalid_input": "re-check the argument types/values against the tool's parameters",
}


def action_for(code: str) -> str:
    """The recovery action for *code*, or ``""`` if none is registered (pure)."""

    return DEFAULT_ACTIONS.get(code, "")


def err(code: str, detail: str = "", action: str | None = None, **extra: object) -> dict:
    """Build a structured error envelope (pure).

    ``{"error": code, "detail": detail, "action": <action or the registered
    default>, **extra}``. *extra* preserves any tool-specific context keys (``url``,
    ``finding_id``, …) the caller wants to keep alongside the error."""

    out: dict = {"error": code, "detail": detail, "action": action or action_for(code)}
    out.update(extra)
    return out
