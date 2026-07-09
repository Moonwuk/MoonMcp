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


def _norm(s: str) -> str:
    return " ".join(str(s).lower().split()).strip(" .:-")


def _signature(f: Finding) -> tuple[str, str, str]:
    """The identity used for dedup: same type + target + title = the same finding."""

    return (_norm(f.type), _norm(f.target), _norm(f.title))


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

    def unique(self) -> list[Finding]:
        """Deduplicated findings — one representative per type+target+title,
        severity-ranked. Non-mutating (used by the report/graph exporters)."""

        seen: dict[tuple[str, str, str], Finding] = {}
        for f in sorted(self._items, key=lambda x: x.id):
            seen.setdefault(_signature(f), f)
        return sorted(seen.values(), key=lambda f: (_sev_rank(f.severity), f.id))

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

    def dedupe(self) -> dict:
        """Collapse exact-duplicate findings (same type + target + title), keeping
        the earliest and folding distinct evidence/source into it. Mutates the
        store; returns how many were removed and the surviving count."""

        seen: dict[tuple[str, str, str], Finding] = {}
        kept: list[Finding] = []
        removed = 0
        for f in sorted(self._items, key=lambda x: x.id):
            sig = _signature(f)
            first = seen.get(sig)
            if first is None:
                seen[sig] = f
                kept.append(f)
                continue
            removed += 1
            if f.evidence and f.evidence not in first.evidence:
                first.evidence = (f"{first.evidence} | {f.evidence}" if first.evidence
                                  else f.evidence)[:2000]
            if f.source and f.source not in first.source:
                first.source = f"{first.source},{f.source}" if first.source else f.source
        self._items = kept
        return {"removed": removed, "remaining": len(kept)}

    def triage(self) -> dict:
        """A prioritised, deduped VIEW of the findings (does not mutate).

        Collapses duplicates, ranks unique findings by severity then frequency,
        and surfaces *systemic* issues — the same finding across multiple targets.
        """

        groups: dict[tuple[str, str, str], list[Finding]] = {}
        for f in self._items:
            groups.setdefault(_signature(f), []).append(f)

        # Cross-target systemic clustering: same type + severity + title, any target.
        systemic_groups: dict[tuple[str, str, str], set[str]] = {}
        for f in self._items:
            key = (_norm(f.type), f.severity, _norm(f.title))
            systemic_groups.setdefault(key, set()).add(f.target)

        unique: list[dict] = []
        for _sig, fs in groups.items():
            rep = min(fs, key=lambda x: x.id)
            targets = sorted({x.target for x in fs})
            key = (_norm(rep.type), rep.severity, _norm(rep.title))
            all_targets = sorted(systemic_groups.get(key, set(targets)))
            unique.append({"finding": asdict(rep), "occurrences": len(fs),
                           "targets": targets, "affected_targets": all_targets})
        unique.sort(key=lambda u: (_sev_rank(u["finding"]["severity"]), -u["occurrences"]))

        by_sev: dict[str, int] = {}
        by_target: dict[str, int] = {}
        for f in self._items:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_target[f.target] = by_target.get(f.target, 0) + 1
        systemic = [u for u in unique if len(u["affected_targets"]) > 1]
        return {
            "total": len(self._items),
            "unique": len(unique),
            "duplicates": len(self._items) - len(unique),
            "by_severity": dict(sorted(by_sev.items(), key=lambda kv: _sev_rank(kv[0]))),
            "top_targets": dict(sorted(by_target.items(), key=lambda kv: -kv[1])[:10]),
            "systemic": systemic[:20],
            "prioritized": unique[:100],
        }

    def as_dict(self, target: str | None = None, severity: str | None = None) -> dict:
        return {"summary": self.summary(),
                "findings": [asdict(f) for f in self.list(target, severity)]}
