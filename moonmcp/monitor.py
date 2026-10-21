"""Bounded attack-surface snapshots with atomic, cooperating persistence."""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import threading
from collections.abc import Iterable
from pathlib import Path

from .persistence import atomic_write, path_lock

_SAFE = re.compile(r"[^a-z0-9_.-]+")


def _safe_name(name: str) -> str:
    key = _SAFE.sub("-", name.strip().lower()) or "default"
    if len(key) > 120:
        raise ValueError("snapshot name exceeds 120 characters")
    return key


class SnapshotStore:
    """Named string sets; corrupt or unconfirmed persistence never re-baselines."""

    def __init__(self, state_dir: str | None = None, *, max_snapshots: int = 256,
                 max_items: int = 10_000, max_bytes: int = 1_000_000) -> None:
        for label, value in (("max_snapshots", max_snapshots),
                             ("max_items", max_items), ("max_bytes", max_bytes)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        self.state_dir = state_dir or None
        self.max_snapshots = max_snapshots
        self.max_items = max_items
        self.max_bytes = max_bytes
        self._mem: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    def _path(self, name: str) -> str | None:
        if self.state_dir is None:
            return None
        return os.path.join(self.state_dir, f"snap-{_safe_name(name)}.json")

    def _directory_lock(self):
        if self.state_dir is None:
            return contextlib.nullcontext()
        return path_lock(os.path.join(self.state_dir, ".snapshots"))

    def _disk_keys(self, *, bounded: bool = True) -> set[str]:
        if self.state_dir is None:
            return set()
        directory = Path(self.state_dir)
        if not directory.exists():
            return set()
        keys = set()
        for path in directory.glob("snap-*.json"):
            key = path.name[len("snap-"):-len(".json")]
            if key != _safe_name(key):
                raise ValueError("snapshot filename is not canonical")
            keys.add(key)
            if bounded and len(keys) > self.max_snapshots:
                raise ValueError("snapshot count exceeds max_snapshots")
        return keys

    def _encoded(self, items: set[str]) -> bytes:
        if len(items) > self.max_items:
            raise ValueError("snapshot exceeds max_items")
        encoded = json.dumps(sorted(items), ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
        if len(encoded) > self.max_bytes:
            raise ValueError("snapshot exceeds max_bytes")
        return encoded

    def _items(self, items: Iterable[str]) -> set[str]:
        values: set[str] = set()
        byte_floor = 2
        for item in items:
            value = str(item).strip()
            if not value or value in values:
                continue
            values.add(value)
            if len(values) > self.max_items:
                raise ValueError("snapshot exceeds max_items")
            byte_floor += len(value.encode("utf-8")) + 2
            if len(values) > 1:
                byte_floor += 1
            if byte_floor > self.max_bytes:
                raise ValueError("snapshot exceeds max_bytes")
        self._encoded(values)
        return values

    def _load(self, name: str) -> set[str] | None:
        key = _safe_name(name)
        path = self._path(key)
        if path is None:
            cached = self._mem.get(key)
            return set(cached) if cached is not None else None
        # Persistent stores always reread: another process may have replaced a
        # baseline. The memory cache never masks corruption or external changes.
        try:
            flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("snapshot baseline must be a regular file")
                if info.st_size > self.max_bytes:
                    raise ValueError("snapshot baseline exceeds max_bytes")
                raw = stream.read(self.max_bytes + 1)
            if len(raw) > self.max_bytes:
                raise ValueError("snapshot baseline exceeds max_bytes")
            data = json.loads(raw)
            if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
                raise ValueError("snapshot baseline must be a JSON string list")
            if len(data) > self.max_items:
                raise ValueError("snapshot baseline exceeds max_items")
        except FileNotFoundError:
            self._mem.pop(key, None)
            return None
        except (OSError, ValueError) as exc:
            raise ValueError(f"snapshot baseline is unreadable or corrupt: {key}") from exc
        # Readers stage validated values; only a complete names() refresh or a
        # confirmed write may advance the cache. Failed reads cannot grow it.
        return set(data)

    def _store(self, name: str, items: set[str]) -> None:
        key = _safe_name(name)
        encoded = self._encoded(items)
        path = self._path(key)
        if path is not None:
            try:
                atomic_write(path, encoded)
            except OSError as exc:
                raise ValueError(f"snapshot update is unconfirmed: {key}") from exc
        # Only a confirmed persisted update may advance the in-memory baseline.
        self._mem[key] = set(items)

    def diff(self, name: str, items: Iterable[str]) -> dict:
        """Diff against a current valid baseline, then atomically replace it."""
        key = _safe_name(name)
        current = self._items(items)
        with self._lock, self._directory_lock():
            known = self._disk_keys() if self.state_dir is not None else set(self._mem)
            if self.state_dir is not None:
                for stale in set(self._mem) - known:
                    self._mem.pop(stale, None)
            if key not in known and len(known) >= self.max_snapshots:
                raise ValueError("snapshot count exceeds max_snapshots")
            previous = self._load(key)
            self._store(key, current)
        if previous is None:
            return {"name": name, "baseline_created": True, "total": len(current),
                    "added": [], "removed": [], "added_count": 0, "removed_count": 0}
        added, removed = sorted(current - previous), sorted(previous - current)
        return {"name": name, "baseline_created": False, "total": len(current),
                "added": added, "removed": removed,
                "added_count": len(added), "removed_count": len(removed)}

    def names(self) -> dict[str, int]:
        with self._lock, self._directory_lock():
            if self.state_dir is None:
                return {name: len(items) for name, items in sorted(self._mem.items())}
            keys = self._disk_keys()
            for key in set(self._mem) - keys:
                self._mem.pop(key, None)
            refreshed = {}
            for key in sorted(keys):
                items = self._load(key)
                if items is not None:
                    refreshed[key] = items
            self._mem = refreshed
            return {key: len(items) for key, items in refreshed.items()}

    def clear(self, name: str | None = None) -> int:
        requested = _safe_name(name) if name is not None else None
        with self._lock, self._directory_lock():
            keys = ({requested} if requested is not None else
                    set(self._mem) | self._disk_keys(bounded=False))
            removed = 0
            for key in keys:
                existed = key in self._mem
                path = self._path(key)
                if path is not None:
                    try:
                        os.unlink(path)
                        existed = True
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        raise ValueError(f"snapshot removal is unconfirmed: {key}") from exc
                self._mem.pop(key, None)
                removed += int(existed)
            if self.state_dir is not None and removed:
                from .persistence import fsync_directory

                try:
                    fsync_directory(os.path.abspath(self.state_dir))
                except OSError as exc:
                    raise ValueError("snapshot removal is unconfirmed") from exc
            return removed
