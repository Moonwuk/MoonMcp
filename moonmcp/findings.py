"""Bounded findings with optional durable SQLite storage and stable identifiers."""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

_LOG = logging.getLogger(__name__)

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.get(str(sev).lower(), 5)


def _norm(s: str) -> str:
    return " ".join(str(s).lower().split()).strip(" .:-")


def _signature(f: Finding) -> tuple[str, str, str, str]:
    """Dedup identity includes the run so separate assessments retain their evidence."""

    return (f.run_id, _norm(f.type), _norm(f.target), _norm(f.title))


# Operator verdicts on whether a recorded finding/lead was real (drives precision).
OUTCOMES = ("true_positive", "false_positive", "duplicate", "wont_fix", "unknown")


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
    outcome: str = ""  # set by label_finding once triaged (see OUTCOMES)
    run_id: str = ""  # empty for historical/unassociated findings


class FindingsStore:
    """Keep the legacy collection API while persisting every mutation atomically.

    Omit ``db_path`` for an isolated in-memory store. IDs never recycle after
    pruning, deduplication or clearing, including across process restarts.
    """

    def __init__(self, cap: int = 2000, *, db_path: str | None = None,
                 run_id_provider: Callable[[], str | None] | None = None,
                 on_record: Callable[[Finding], None] | None = None) -> None:
        if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
            raise ValueError("cap must be a positive integer")
        self.cap = cap
        self.run_id_provider = run_id_provider
        self.on_record = on_record
        self.db_path = db_path or ":memory:"
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("""CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
            severity TEXT NOT NULL, title TEXT NOT NULL, type TEXT NOT NULL,
            detail TEXT NOT NULL, evidence TEXT NOT NULL, source TEXT NOT NULL,
            created_at TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT '')""")
        if self.db_path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in self._db.execute("PRAGMA table_info(findings)")}
            if "run_id" not in columns:
                self._db.execute("ALTER TABLE findings ADD COLUMN run_id TEXT NOT NULL DEFAULT ''")
            self._db.execute("CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id,id)")

    @classmethod
    def from_env(cls, state_dir: str | None, *,
                 run_id_provider: Callable[[], str | None] | None = None,
                 on_record: Callable[[Finding], None] | None = None) -> FindingsStore:
        return cls(db_path=str(Path(state_dir) / "findings.db") if state_dir else None,
                   run_id_provider=run_id_provider, on_record=on_record)

    @property
    def _items(self) -> list[Finding]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM findings ORDER BY id").fetchall()
        return [Finding(**dict(row)) for row in rows]

    def add(self, *, target: str, severity: str, title: str, type: str = "manual",
            detail: str = "", evidence: str = "", source: str = "", created_at: str = "",
            run_id: str | None = None) -> Finding:
        """Record evidence, inferring run association only when not explicitly supplied."""
        if run_id is None:
            run_id = self.run_id_provider() if self.run_id_provider is not None else ""
            if run_id is None:
                run_id = ""
        if not isinstance(run_id, str):
            raise ValueError("run_id must be a string")
        sev = str(severity).lower()
        if sev not in _SEV_ORDER:
            sev = "info"
        with self._lock, self._db:
            cur = self._db.execute(
                """INSERT INTO findings(target,severity,title,type,detail,evidence,source,created_at,run_id)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (target, sev, title, type, detail, evidence, source, created_at, run_id),
            )
            assert cur.lastrowid is not None
            finding = Finding(id=int(cur.lastrowid), target=target, severity=sev, title=title,
                              type=type, detail=detail, evidence=evidence, source=source,
                              created_at=created_at, run_id=run_id)
            self._db.execute("""DELETE FROM findings WHERE id NOT IN
                (SELECT id FROM findings ORDER BY id DESC LIMIT ?)""", (self.cap,))
        if self.on_record is not None:
            try:
                self.on_record(finding)
            except Exception as exc:
                # Observability failure must not make a durable write look failed,
                # tempting callers to retry and create a second finding.
                _LOG.warning("Finding observer failed: %s", exc.__class__.__name__)
        return finding

    def set_outcome(self, finding_id: int, outcome: str) -> Finding | None:
        """Label a persisted finding's real-world outcome for precision metrics."""
        oc = str(outcome).strip().lower()
        if oc not in OUTCOMES:
            oc = "unknown"
        with self._lock, self._db:
            self._db.execute("UPDATE findings SET outcome=? WHERE id=?", (oc, finding_id))
            row = self._db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return Finding(**dict(row)) if row is not None else None

    def unique(self) -> list[Finding]:
        """Deduplicated findings — one representative per type+target+title,
        severity-ranked. Non-mutating (used by the report/graph exporters)."""

        seen: dict[tuple[str, str, str, str], Finding] = {}
        for f in sorted(self._items, key=lambda x: x.id):
            seen.setdefault(_signature(f), f)
        return sorted(seen.values(), key=lambda f: (_sev_rank(f.severity), f.id))

    def list(self, target: str | None = None, severity: str | None = None, *,
             run_id: str | None = None) -> list[Finding]:
        if run_id is None:
            items = self._items
        else:
            with self._lock:
                rows = self._db.execute("SELECT * FROM findings WHERE run_id=? ORDER BY id",
                                        (run_id,)).fetchall()
            items = [Finding(**dict(row)) for row in rows]
        if target:
            t = target.lower().lstrip("*.")
            items = [f for f in items if f.target.lower() == t or f.target.lower().endswith("." + t)]
        if severity:
            items = [f for f in items if f.severity == severity.lower()]
        return sorted(items, key=lambda f: (_sev_rank(f.severity), f.id))

    def clear(self, target: str | None = None) -> int:
        with self._lock, self._db:
            if target is None:
                cur = self._db.execute("DELETE FROM findings")
            else:
                cur = self._db.execute("DELETE FROM findings WHERE lower(target)=?",
                                       (target.lower(),))
            return cur.rowcount

    def summary(self, *, run_id: str | None = None) -> dict:
        items = self.list(run_id=run_id)
        counts: dict[str, int] = {}
        for f in items:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {"total": len(items),
                "by_severity": dict(sorted(counts.items(), key=lambda kv: _sev_rank(kv[0])))}

    def dedupe(self) -> dict:
        """Collapse exact-duplicate findings (same run + type + target + title), keeping
        the earliest and folding distinct evidence/source into it. Mutates the
        store; returns how many were removed and the surviving count."""

        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            items = self._items
            seen: dict[tuple[str, str, str, str], Finding] = {}
            kept: list[Finding] = []
            removed = 0
            for f in sorted(items, key=lambda x: x.id):
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
            for finding in kept:
                self._db.execute("UPDATE findings SET evidence=?,source=? WHERE id=?",
                                 (finding.evidence, finding.source, finding.id))
            keep_ids = {finding.id for finding in kept}
            self._db.executemany("DELETE FROM findings WHERE id=?",
                                 [(finding.id,) for finding in items if finding.id not in keep_ids])
            return {"removed": removed, "remaining": len(kept)}

    def triage(self) -> dict:
        """A prioritised, deduped VIEW of the findings (does not mutate).

        Collapses duplicates, ranks unique findings by severity then frequency,
        and surfaces *systemic* issues — the same finding across multiple targets.
        """

        items = self._items
        groups: dict[tuple[str, str, str, str], list[Finding]] = {}
        for f in items:
            groups.setdefault(_signature(f), []).append(f)

        # Cross-target systemic clustering: same type + severity + title, any target.
        systemic_groups: dict[tuple[str, str, str], set[str]] = {}
        for f in items:
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
        for f in items:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_target[f.target] = by_target.get(f.target, 0) + 1
        systemic = [u for u in unique if len(u["affected_targets"]) > 1]
        return {
            "total": len(items),
            "unique": len(unique),
            "duplicates": len(items) - len(unique),
            "by_severity": dict(sorted(by_sev.items(), key=lambda kv: _sev_rank(kv[0]))),
            "top_targets": dict(sorted(by_target.items(), key=lambda kv: -kv[1])[:10]),
            "systemic": systemic[:20],
            "prioritized": unique[:100],
        }

    def as_dict(self, target: str | None = None, severity: str | None = None, *,
                run_id: str | None = None) -> dict:
        return {"summary": self.summary(run_id=run_id),
                "findings": [asdict(f) for f in self.list(target, severity, run_id=run_id)]}

    def close(self) -> None:
        with self._lock:
            self._db.close()
