"""Attack-surface change tracking (baseline + diff).

Recon is a loop, not a one-shot: assets appear and disappear.  A named snapshot
of any set of strings — subdomains, live hosts, endpoints, params — can be diffed
against the next run so the operator sees *only what is new* (freshly exposed,
under-competed surface) instead of re-triaging everything.

Snapshots live in memory for the session; if ``MOONMCP_STATE_DIR`` is set they
also persist to disk as JSON, so a long-running / scheduled MoonMCP can monitor
across runs.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable

_SAFE = re.compile(r"[^a-z0-9_.-]+")


def _safe_name(name: str) -> str:
    return _SAFE.sub("-", name.strip().lower()) or "default"


class SnapshotStore:
    """Named snapshots of string sets, diffed across runs (optional disk persistence)."""

    def __init__(self, state_dir: str | None = None) -> None:
        self.state_dir = state_dir or None
        self._mem: dict[str, set[str]] = {}

    def _path(self, name: str) -> str | None:
        if not self.state_dir:
            return None
        return os.path.join(self.state_dir, f"snap-{_safe_name(name)}.json")

    def _load(self, name: str) -> set[str] | None:
        if name in self._mem:
            return self._mem[name]
        path = self._path(name)
        if path and os.path.exists(path):
            try:
                with open(path) as fh:
                    data = json.load(fh)
                s = {str(x) for x in data}
                self._mem[name] = s
                return s
            except (OSError, ValueError):
                return None
        return None

    def _store(self, name: str, items: set[str]) -> None:
        self._mem[name] = items
        path = self._path(name)
        if path:
            try:
                os.makedirs(self.state_dir, exist_ok=True)  # type: ignore[arg-type]
                with open(path, "w") as fh:
                    json.dump(sorted(items), fh)
            except OSError:
                pass

    def diff(self, name: str, items: Iterable[str]) -> dict:
        """Diff *items* against snapshot *name*; then update the snapshot.

        First call for a name establishes the baseline (nothing is "new" yet);
        subsequent calls return what was added / removed since last time.
        """

        cur = {str(i).strip() for i in items if str(i).strip()}
        prev = self._load(name)
        self._store(name, cur)
        if prev is None:
            return {"name": name, "baseline_created": True, "total": len(cur),
                    "added": [], "removed": [], "added_count": 0, "removed_count": 0}
        added = sorted(cur - prev)
        removed = sorted(prev - cur)
        return {"name": name, "baseline_created": False, "total": len(cur),
                "added": added, "removed": removed,
                "added_count": len(added), "removed_count": len(removed)}

    def names(self) -> dict[str, int]:
        return {n: len(s) for n, s in sorted(self._mem.items())}

    def clear(self, name: str | None = None) -> int:
        if name is None:
            n = len(self._mem)
            self._mem.clear()
            return n
        removed = 1 if self._mem.pop(name, None) is not None else 0
        path = self._path(name)
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
        return removed
