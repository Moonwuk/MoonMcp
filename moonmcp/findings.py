"""Session-scoped findings store.

A small, bounded, in-memory collection of findings that tools (and the LLM) can
record during an engagement, exposed both as tools and as the ``findings://``
MCP resource so a client can read the running list without spending tool-call
tokens.  Deliberately not persisted to disk — it lives for the session only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.get(str(sev).lower(), 5)


@dataclass
class Finding:
    id: int
    target: str
    severity: str
    title: str
    type: str = "manual"
    detail: str = ""
    evidence: str = ""
    source: str = ""
    created_at: str = ""


@dataclass
class FindingsStore:
    cap: int = 2000
    _items: list[Finding] = field(default_factory=list)
    _next_id: int = 1

    def add(self, *, target: str, severity: str, title: str, type: str = "manual",
            detail: str = "", evidence: str = "", source: str = "", created_at: str = "") -> Finding:
        sev = str(severity).lower()
        if sev not in _SEV_ORDER:
            sev = "info"
        f = Finding(id=self._next_id, target=target, severity=sev, title=title, type=type,
                    detail=detail, evidence=evidence, source=source, created_at=created_at)
        self._next_id += 1
        self._items.append(f)
        if len(self._items) > self.cap:
            self._items = self._items[-self.cap:]
        return f

    def list(self, target: str | None = None, severity: str | None = None) -> list[Finding]:
        items = self._items
        if target:
            t = target.lower().lstrip("*.")
            items = [f for f in items if f.target.lower() == t or f.target.lower().endswith("." + t)]
        if severity:
            items = [f for f in items if f.severity == severity.lower()]
        return sorted(items, key=lambda f: (_sev_rank(f.severity), f.id))

    def clear(self, target: str | None = None) -> int:
        if target is None:
            n = len(self._items)
            self._items = []
            return n
        t = target.lower()
        before = len(self._items)
        self._items = [f for f in self._items if f.target.lower() != t]
        return before - len(self._items)

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for f in self._items:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {"total": len(self._items),
                "by_severity": dict(sorted(counts.items(), key=lambda kv: _sev_rank(kv[0])))}

    def as_dict(self, target: str | None = None, severity: str | None = None) -> dict:
        return {"summary": self.summary(),
                "findings": [asdict(f) for f in self.list(target, severity)]}
