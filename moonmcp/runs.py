"""Persistent engagement runs, task coordination, coverage and budgets.

This is the execution-state layer between MoonMCP's deterministic security tools
and an agent host.  It intentionally does not contain an LLM: any MCP client can
coordinate a resumable assessment through the same small state machine.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RUN_STATES = {"running", "paused", "completed", "cancelled", "failed"}
TASK_STATES = {"pending", "running", "blocked", "completed", "failed", "cancelled"}
ROLES = {"coordinator", "mapper", "hypothesis", "validator", "reporter"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RunBudget:
    max_requests: int = 1000
    max_tool_calls: int = 250
    max_intrusive_calls: int = 25

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    focus TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    max_requests INTEGER NOT NULL,
    max_tool_calls INTEGER NOT NULL,
    max_intrusive_calls INTEGER NOT NULL,
    requests_used INTEGER NOT NULL DEFAULT 0,
    tool_calls_used INTEGER NOT NULL DEFAULT 0,
    intrusive_calls_used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    role TEXT NOT NULL,
    state TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    depends_on INTEGER REFERENCES tasks(id),
    detail TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS coverage (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    item TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, item)
);
CREATE TABLE IF NOT EXISTS run_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_run_state ON tasks(run_id, state, priority, id);
CREATE INDEX IF NOT EXISTS idx_events_run ON run_events(run_id, id);
CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id, id);
"""


class RunStore:
    """SQLite-backed run state that can be resumed by another process/session."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or ":memory:"
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            if self.path != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.commit()

    @classmethod
    def from_env(cls, state_dir: str | None) -> RunStore:
        return cls(str(Path(state_dir) / "runs.db") if state_dir else None)

    def _event(self, run_id: str, kind: str, payload: dict[str, Any]) -> None:
        self._db.execute(
            "INSERT INTO run_events(run_id,kind,payload,created_at) VALUES(?,?,?,?)",
            (run_id, kind, json.dumps(payload, sort_keys=True), _now()),
        )

    def create(self, target: str, *, focus: str = "", budget: RunBudget | None = None) -> dict:
        target = target.strip()
        if not target:
            raise ValueError("target is required")
        budget = budget or RunBudget()
        budget.validate()
        run_id = uuid.uuid4().hex[:16]
        now = _now()
        with self._lock:
            self._db.execute(
                """INSERT INTO runs(id,target,focus,state,created_at,updated_at,
                   max_requests,max_tool_calls,max_intrusive_calls) VALUES(?,?,?,?,?,?,?,?,?)""",
                (run_id, target, focus.strip(), "running", now, now,
                 budget.max_requests, budget.max_tool_calls, budget.max_intrusive_calls),
            )
            self._event(run_id, "run_started", {"target": target, "focus": focus.strip()})
            self._db.commit()
        return self.get(run_id)

    def get(self, run_id: str) -> dict:
        with self._lock:
            row = self._db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise ValueError(f"unknown run: {run_id}")
            out = dict(row)
            out["budget"] = {
                "requests": {"used": out.pop("requests_used"), "max": out.pop("max_requests")},
                "tool_calls": {"used": out.pop("tool_calls_used"), "max": out.pop("max_tool_calls")},
                "intrusive_calls": {
                    "used": out.pop("intrusive_calls_used"),
                    "max": out.pop("max_intrusive_calls"),
                },
            }
            out["tasks"] = self.task_counts(run_id)
            out["coverage"] = self.coverage_summary(run_id)
            return out

    def list_runs(self, *, state: str | None = None, limit: int = 50) -> list[dict]:
        if state is not None and state not in RUN_STATES:
            raise ValueError(f"invalid run state: {state}")
        limit = max(1, min(int(limit), 200))
        query = "SELECT id FROM runs"
        args: tuple[Any, ...] = ()
        if state:
            query += " WHERE state=?"
            args = (state,)
        query += " ORDER BY created_at DESC LIMIT ?"
        with self._lock:
            ids = [r[0] for r in self._db.execute(query, (*args, limit)).fetchall()]
        return [self.get(run_id) for run_id in ids]

    def set_state(self, run_id: str, state: str) -> dict:
        if state not in RUN_STATES:
            raise ValueError(f"invalid run state: {state}")
        self.get(run_id)
        with self._lock:
            self._db.execute(
                "UPDATE runs SET state=?, updated_at=? WHERE id=?", (state, _now(), run_id)
            )
            self._event(run_id, "run_state", {"state": state})
            self._db.commit()
        return self.get(run_id)

    def add_task(self, run_id: str, title: str, *, role: str = "coordinator",
                 priority: int = 50, depends_on: int | None = None,
                 detail: str = "") -> dict:
        self.get(run_id)
        title = title.strip()
        if not title:
            raise ValueError("task title is required")
        if role not in ROLES:
            raise ValueError(f"invalid role: {role}")
        priority = max(0, min(int(priority), 100))
        now = _now()
        with self._lock:
            if depends_on is not None:
                parent = self._db.execute(
                    "SELECT run_id FROM tasks WHERE id=?", (depends_on,)
                ).fetchone()
                if parent is None or parent[0] != run_id:
                    raise ValueError("depends_on must identify a task in the same run")
            cur = self._db.execute(
                """INSERT INTO tasks(run_id,title,role,state,priority,depends_on,detail,
                   created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (run_id, title, role, "pending", priority, depends_on, detail, now, now),
            )
            if cur.lastrowid is None:  # pragma: no cover - SQLite always supplies it
                raise RuntimeError("SQLite did not return a task id")
            task_id = int(cur.lastrowid)
            self._event(run_id, "task_added", {"task_id": task_id, "role": role})
            self._db.commit()
        return self.task(task_id)

    def task(self, task_id: int) -> dict:
        with self._lock:
            row = self._db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None:
            raise ValueError(f"unknown task: {task_id}")
        return dict(row)

    def update_task(self, task_id: int, state: str, *, result: str = "") -> dict:
        if state not in TASK_STATES:
            raise ValueError(f"invalid task state: {state}")
        task = self.task(task_id)
        with self._lock:
            self._db.execute(
                "UPDATE tasks SET state=?, result=?, updated_at=? WHERE id=?",
                (state, result, _now(), task_id),
            )
            self._event(task["run_id"], "task_state", {"task_id": task_id, "state": state})
            self._db.commit()
        return self.task(task_id)

    def tasks(self, run_id: str, *, state: str | None = None) -> list[dict]:
        self.get(run_id)
        if state is not None and state not in TASK_STATES:
            raise ValueError(f"invalid task state: {state}")
        query = "SELECT * FROM tasks WHERE run_id=?"
        args: tuple[Any, ...] = (run_id,)
        if state:
            query += " AND state=?"
            args += (state,)
        query += " ORDER BY priority DESC,id"
        with self._lock:
            return [dict(row) for row in self._db.execute(query, args).fetchall()]

    def task_counts(self, run_id: str) -> dict[str, int]:
        rows = self._db.execute(
            "SELECT state,COUNT(*) FROM tasks WHERE run_id=? GROUP BY state", (run_id,)
        ).fetchall()
        return {str(state): int(count) for state, count in rows}

    def next_task(self, run_id: str) -> dict | None:
        self.get(run_id)
        with self._lock:
            row = self._db.execute(
                """SELECT t.* FROM tasks t LEFT JOIN tasks dependency ON dependency.id=t.depends_on
                   WHERE t.run_id=? AND t.state='pending'
                   AND (t.depends_on IS NULL OR dependency.state='completed')
                   ORDER BY t.priority DESC,t.id LIMIT 1""",
                (run_id,),
            ).fetchone()
        return dict(row) if row else None

    def set_coverage(self, run_id: str, item: str, status: str,
                     *, evidence: str = "") -> dict:
        self.get(run_id)
        item = item.strip()
        if not item:
            raise ValueError("coverage item is required")
        if status not in {"open", "in_progress", "covered", "not_applicable", "blocked"}:
            raise ValueError(f"invalid coverage status: {status}")
        now = _now()
        with self._lock:
            self._db.execute(
                """INSERT INTO coverage(run_id,item,status,evidence,updated_at) VALUES(?,?,?,?,?)
                   ON CONFLICT(run_id,item) DO UPDATE SET
                   status=excluded.status,evidence=excluded.evidence,updated_at=excluded.updated_at""",
                (run_id, item, status, evidence, now),
            )
            self._event(run_id, "coverage", {"item": item, "status": status})
            self._db.commit()
        return {"run_id": run_id, "item": item, "status": status, "evidence": evidence,
                "updated_at": now}

    def coverage_summary(self, run_id: str) -> dict:
        rows = self._db.execute(
            "SELECT status,COUNT(*) FROM coverage WHERE run_id=? GROUP BY status", (run_id,)
        ).fetchall()
        counts = {str(status): int(count) for status, count in rows}
        total = sum(counts.values())
        satisfied = counts.get("covered", 0) + counts.get("not_applicable", 0)
        return {"total": total, "counts": counts,
                "percent": round(100 * satisfied / total, 1) if total else 0.0}

    def consume(self, run_id: str, *, requests: int = 0, tool_calls: int = 0,
                intrusive_calls: int = 0) -> dict:
        values = {"requests": requests, "tool_calls": tool_calls,
                  "intrusive_calls": intrusive_calls}
        if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in values.values()):
            raise ValueError("usage increments must be non-negative integers")
        with self._lock:
            self.get(run_id)
            cur = self._db.execute(
                """UPDATE runs SET requests_used=requests_used+?,
                   tool_calls_used=tool_calls_used+?,intrusive_calls_used=intrusive_calls_used+?,
                   updated_at=? WHERE id=?
                   AND requests_used+?<=max_requests
                   AND tool_calls_used+?<=max_tool_calls
                   AND intrusive_calls_used+?<=max_intrusive_calls""",
                (requests, tool_calls, intrusive_calls, _now(), run_id,
                 requests, tool_calls, intrusive_calls),
            )
            if cur.rowcount != 1:
                run = self.get(run_id)
                exhausted = [
                    name for name, increment in values.items()
                    if run["budget"][name]["used"] + increment > run["budget"][name]["max"]
                ]
                raise ValueError("budget exceeded: " + ", ".join(exhausted))
            self._event(run_id, "usage", values)
            self._db.commit()
        return self.get(run_id)

    def finish(self, run_id: str, *, force: bool = False) -> dict:
        run = self.get(run_id)
        open_tasks = sum(run["tasks"].get(s, 0) for s in ("pending", "running", "blocked"))
        uncovered = (run["coverage"]["counts"].get("open", 0)
                     + run["coverage"]["counts"].get("in_progress", 0))
        blockers = []
        if open_tasks:
            blockers.append(f"{open_tasks} unfinished task(s)")
        if uncovered:
            blockers.append(f"{uncovered} uncovered item(s)")
        if blockers and not force:
            return {"completed": False, "run": run, "blockers": blockers,
                    "hint": "finish the work or call again with force=true"}
        return {"completed": True, "run": self.set_state(run_id, "completed"),
                "forced": bool(blockers), "blockers": blockers}

    def events(self, run_id: str, *, limit: int = 100) -> list[dict]:
        self.get(run_id)
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM run_events WHERE run_id=? ORDER BY id DESC LIMIT ?",
                (run_id, max(1, min(int(limit), 500))),
            ).fetchall()
        out = []
        for row in reversed(rows):
            event = dict(row)
            event["payload"] = json.loads(event["payload"])
            out.append(event)
        return out

    def add_artifact(self, run_id: str, kind: str, name: str, content: str) -> dict:
        """Persist bounded evidence or output and return its immutable digest."""

        self.get(run_id)
        kind, name = kind.strip(), name.strip()
        if not kind or not name:
            raise ValueError("artifact kind and name are required")
        encoded = content.encode("utf-8", errors="replace")
        if len(encoded) > 1_000_000:
            raise ValueError("artifact content exceeds the 1 MB limit")
        digest = hashlib.sha256(encoded).hexdigest()
        now = _now()
        with self._lock:
            cur = self._db.execute(
                """INSERT INTO artifacts(run_id,kind,name,content,sha256,created_at)
                   VALUES(?,?,?,?,?,?)""", (run_id, kind, name, content, digest, now)
            )
            if cur.lastrowid is None:  # pragma: no cover
                raise RuntimeError("SQLite did not return an artifact id")
            artifact_id = int(cur.lastrowid)
            self._event(run_id, "artifact_added", {"artifact_id": artifact_id,
                                                    "kind": kind, "sha256": digest})
            self._db.commit()
        return {"id": artifact_id, "run_id": run_id, "kind": kind, "name": name,
                "sha256": digest, "size": len(encoded), "created_at": now}

    def artifacts(self, run_id: str, *, include_content: bool = False,
                  limit: int = 100) -> list[dict]:
        self.get(run_id)
        columns = "*" if include_content else "id,run_id,kind,name,sha256,created_at"
        with self._lock:
            rows = self._db.execute(
                f"SELECT {columns} FROM artifacts WHERE run_id=? ORDER BY id LIMIT ?",  # noqa: S608
                (run_id, max(1, min(int(limit), 500))),
            ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        """Close the underlying SQLite connection (idempotent best effort)."""

        try:
            self._db.close()
        except sqlite3.Error:
            pass

    def __del__(self) -> None:  # pragma: no cover - interpreter/GC timing dependent
        self.close()


def seed_assessment(store: RunStore, run_id: str) -> list[dict]:
    """Create a small dependency-ordered team plan for a new assessment."""

    orient = store.add_task(run_id, "Recall prior knowledge and validate scope",
                            role="coordinator", priority=100)
    mapping = store.add_task(run_id, "Map the authorised attack surface", role="mapper",
                             priority=90, depends_on=orient["id"])
    hypotheses = store.add_task(run_id, "Generate evidence-backed vulnerability hypotheses",
                                role="hypothesis", priority=80, depends_on=mapping["id"])
    validate = store.add_task(run_id, "Validate high-value leads with reproducible controls",
                              role="validator", priority=70, depends_on=hypotheses["id"])
    report = store.add_task(run_id, "Triage findings and produce the final report",
                            role="reporter", priority=60, depends_on=validate["id"])
    for item in ("scope", "passive_recon", "attack_surface", "auth_surface",
                 "vulnerability_hypotheses", "lead_validation", "reporting"):
        store.set_coverage(run_id, item, "open")
    return [orient, mapping, hypotheses, validate, report]
