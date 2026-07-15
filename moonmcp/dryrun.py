"""Dry-run previews for intrusive probes.

Every intrusive probe fires a battery of payloads at a target. Before letting one
loose, an operator (or a human confirming an agent's plan) often wants to see
*exactly* what it would send. A wired probe takes ``dry_run=True`` and returns this
preview — the method, the injected parameter, and the payload list it WOULD send —
**without sending anything**. It's the see-before-you-fire counterpart to the
detection run, and it needs no intrusive switch (nothing leaves the process); the
scope guard still applies.

Purely a formatter — no network, no state.
"""

from __future__ import annotations

from collections.abc import Iterable

_MAX = 60  # cap the previewed payload list so a large battery doesn't flood context


def preview(*, probe: str, target: str, payloads: Iterable[str],
            method: str = "GET", param: str | None = None,
            note: str = "", **extra: object) -> dict:
    """Build a dry-run preview envelope (pure). *payloads* is the list of payload
    strings the probe would inject; *extra* carries any probe-specific context."""

    pv = [str(p) for p in payloads]
    out: dict = {
        "dry_run": True,
        "probe": probe,
        "target": target,
        "method": method,
        "param": param,
        "payload_count": len(pv),
        "payloads": pv[:_MAX],
        "note": note or "preview only — nothing was sent; call again with dry_run=False to execute",
    }
    if len(pv) > _MAX:
        out["_truncated"] = len(pv) - _MAX
    out.update(extra)
    return out
