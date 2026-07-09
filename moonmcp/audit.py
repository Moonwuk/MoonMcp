"""Logging + an append-only audit log.

Two things the gap analysis flagged as missing:

* **Logging** — a ``moonmcp`` logger that writes to **stderr** (never stdout, which
  the stdio MCP transport reserves for the JSON-RPC protocol), level via
  ``MOONMCP_LOG_LEVEL``.
* **Audit log** — one structured record per scope decision / external command, kept
  in a bounded in-memory ring (exposed on the ``audit://recent`` resource) and,
  when ``MOONMCP_AUDIT_LOG`` is set, appended as JSONL to disk.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

_LOGGER_NAME = "moonmcp"


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)


def setup_logging(level: str | None = None) -> logging.Logger:
    """Configure the moonmcp logger to emit to stderr (idempotent)."""

    logger = logging.getLogger(_LOGGER_NAME)
    if getattr(logger, "_moonmcp_configured", False):
        return logger
    lvl = (level or os.environ.get("MOONMCP_LOG_LEVEL", "WARNING")).upper()
    handler = logging.StreamHandler(sys.stderr)  # NEVER stdout — stdio MCP uses it
    handler.setFormatter(logging.Formatter("%(asctime)s moonmcp[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, lvl, logging.WARNING))
    logger.propagate = False
    logger._moonmcp_configured = True  # type: ignore[attr-defined]
    return logger


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class AuditLog:
    """A bounded, structured audit trail of security-relevant actions."""

    path: str | None = None
    cap: int = 1000
    _events: deque = field(default_factory=deque)

    def __post_init__(self) -> None:
        self._events = deque(maxlen=self.cap)

    @classmethod
    def from_env(cls) -> AuditLog:
        return cls(path=os.environ.get("MOONMCP_AUDIT_LOG") or None)

    def record(self, event: str, **fields) -> dict:
        entry = {"ts": _now(), "event": event, **fields}
        self._events.append(entry)
        if self.path:
            try:
                with open(self.path, "a") as fh:
                    fh.write(json.dumps(entry) + "\n")
            except OSError as exc:
                get_logger().warning("audit write to %s failed: %s", self.path, exc)
        # mirror the key facts to the stderr logger (INFO)
        get_logger().info(
            "audit %s tool=%s target=%s decision=%s",
            event, fields.get("tool"), fields.get("target"), fields.get("decision"),
        )
        return entry

    def recent(self, limit: int = 100) -> list[dict]:
        items = list(self._events)
        return items[-limit:] if limit and limit > 0 else items

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for e in self._events:
            counts[e["event"]] = counts.get(e["event"], 0) + 1
        return {"total": len(self._events), "by_event": counts,
                "persisted_to": self.path or None}
