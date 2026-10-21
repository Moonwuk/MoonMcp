"""Stderr logging and a bounded, durable, structured audit trail."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import sys
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .persistence import fsync_directory, path_lock

_LOGGER_NAME = "moonmcp"
_MAX_RECORD_BYTES = 65_536


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)


def setup_logging(level: str | None = None) -> logging.Logger:
    """Configure only MoonMCP's own stderr handler; refresh captured streams."""
    logger = get_logger()
    managed = [handler for handler in logger.handlers
               if getattr(handler, "_moonmcp_stderr", False)]
    if not managed:
        handler = logging.StreamHandler(sys.stderr)
        handler._moonmcp_stderr = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
        managed = [handler]
    for managed_handler in managed:
        if isinstance(managed_handler, logging.StreamHandler):
            try:
                managed_handler.setStream(sys.stderr)
            except (OSError, ValueError):
                # A previous test/client capture stream may already be closed.
                managed_handler.stream = sys.stderr
            managed_handler.setFormatter(logging.Formatter(
                "%(asctime)s moonmcp[%(levelname)s] %(message)s"))
    lvl = (level or os.environ.get("MOONMCP_LOG_LEVEL", "WARNING")).upper()
    logger.setLevel(getattr(logging, lvl, logging.WARNING))
    logger.propagate = False
    logger._moonmcp_configured = True  # type: ignore[attr-defined]
    return logger


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


@dataclass
class AuditLog:
    """Bounded memory plus rotating JSONL; persistence errors remain observable."""

    path: str | None = None
    cap: int = 1000
    _events: deque = field(default_factory=deque, repr=False)
    max_bytes: int = 4 * 1024 * 1024
    backup_count: int = 3
    fsync: bool = True
    _lock: Any = field(init=False, repr=False)
    _write_error: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.path is not None:
            self.path = os.fsdecode(self.path)
        if isinstance(self.cap, bool) or not isinstance(self.cap, int) or self.cap < 0:
            raise ValueError("audit cap must be a non-negative integer")
        if (isinstance(self.max_bytes, bool) or not isinstance(self.max_bytes, int)
                or self.max_bytes < 512):
            raise ValueError("audit max_bytes must be an integer of at least 512")
        if (isinstance(self.backup_count, bool) or not isinstance(self.backup_count, int)
                or not 0 <= self.backup_count <= 20):
            raise ValueError("audit backup_count must be an integer from 0 to 20")
        if not isinstance(self.fsync, bool):
            raise ValueError("audit fsync must be a boolean")
        self._events = deque(maxlen=self.cap)
        self._lock = threading.RLock()

    @classmethod
    def from_env(cls) -> AuditLog:
        return cls(path=os.environ.get("MOONMCP_AUDIT_LOG") or None,
                   max_bytes=_env_int("MOONMCP_AUDIT_MAX_BYTES", 4 * 1024 * 1024),
                   backup_count=_env_int("MOONMCP_AUDIT_BACKUPS", 3),
                   fsync=_env_bool("MOONMCP_AUDIT_FSYNC", True))

    def _rotate(self) -> None:
        assert self.path is not None
        for number in range(self.backup_count, 1, -1):
            try:
                os.replace(f"{self.path}.{number - 1}", f"{self.path}.{number}")
            except FileNotFoundError:
                pass
        try:
            if self.backup_count:
                # Preserve a legacy oversized segment whole, never a partial tail.
                os.replace(self.path, self.path + ".1")
            else:
                os.unlink(self.path)
        except FileNotFoundError:
            pass
        if self.fsync:
            fsync_directory(os.path.dirname(os.path.abspath(self.path)))

    def _append(self, line: bytes) -> None:
        assert self.path is not None
        flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
        with path_lock(self.path):
            fd = os.open(self.path, flags, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise OSError("audit path must be a regular file")
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                if info.st_size + len(line) > self.max_bytes:
                    os.close(fd)
                    fd = -1
                    self._rotate()
                    fd = os.open(self.path, flags, 0o600)
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise OSError("audit path must be a regular file")
                with os.fdopen(fd, "ab") as stream:
                    fd = -1
                    stream.write(line)
                    stream.flush()
                    if self.fsync:
                        os.fsync(stream.fileno())
                if self.fsync:
                    fsync_directory(os.path.dirname(os.path.abspath(self.path)))
            finally:
                if fd >= 0:
                    os.close(fd)

    def record(self, event_name: str | None = None, **fields) -> dict:
        # Retain record(event="name") compatibility. When a positional event is
        # supplied, target/caller fields can never replace it or the timestamp.
        if event_name is None:
            event_name = fields.pop("event", None)
        if not isinstance(event_name, str) or not event_name:
            raise ValueError("audit event must be a nonempty string")
        entry = {**fields, "ts": _now(), "event": event_name}
        line = (json.dumps(entry, ensure_ascii=False, separators=(",", ":"),
                           allow_nan=False) + "\n").encode("utf-8")
        if len(line) > min(self.max_bytes, _MAX_RECORD_BYTES):
            entry = {"ts": entry["ts"], "event": event_name[:16], "oversized": True,
                     "original_bytes": len(line), "sha256": hashlib.sha256(line).hexdigest()}
            line = (json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            self._events.append(dict(entry))
            if self.path:
                try:
                    self._append(line)
                except OSError as exc:
                    self._write_error = str(exc)
                    get_logger().warning("audit write to %s failed: %s", self.path, exc)
        get_logger().info("audit %s tool=%s target=%s decision=%s",
                          event_name, fields.get("tool"), fields.get("target"), fields.get("decision"))
        return entry

    def recent(self, limit: int = 100) -> list[dict]:
        if limit <= 0:
            return []
        with self._lock:
            return [dict(entry) for entry in list(self._events)[-limit:]]

    def summary(self) -> dict:
        with self._lock:
            counts: dict[str, int] = {}
            for entry in self._events:
                counts[entry["event"]] = counts.get(entry["event"], 0) + 1
            return {"total": len(self._events), "by_event": counts,
                    "persisted_to": self.path or None, "write_error": self._write_error,
                    "retention": {"max_bytes": self.max_bytes, "backup_count": self.backup_count,
                                  "max_record_bytes": min(self.max_bytes, _MAX_RECORD_BYTES),
                                  "fsync": self.fsync}}
