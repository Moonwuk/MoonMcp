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
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RUN_STATES = {"running", "paused", "completed", "cancelled", "failed"}
TASK_STATES = {"pending", "running", "blocked", "completed", "failed", "cancelled"}
RUN_TRANSITIONS = {
    "running": {"paused", "completed", "cancelled", "failed"},
    "paused": {"running", "completed", "cancelled", "failed"},
    "completed": set(), "cancelled": set(), "failed": set(),
}
TASK_TRANSITIONS = {
    "pending": {"running", "blocked", "completed", "failed", "cancelled"},
    "running": {"blocked", "completed", "failed", "cancelled"},
    "blocked": {"completed", "failed", "cancelled"},
    "completed": set(), "failed": set(), "cancelled": set(),
}
INVOCATION_STATES = {"running", "completed", "failed", "unknown", "cancelled"}
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
CREATE TABLE IF NOT EXISTS invocations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    task_id INTEGER REFERENCES tasks(id),
    tool_name TEXT NOT NULL,
    arguments_hash TEXT NOT NULL,
    idempotency_key TEXT,
    state TEXT NOT NULL,
    result TEXT,
    requests_used INTEGER NOT NULL DEFAULT 0,
    intrusive INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS invocation_resolutions (
    invocation_id TEXT PRIMARY KEY REFERENCES invocations(id),
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_artifact_ids TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invocations_run ON invocations(run_id, state);
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
            self._db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in self._db.execute("PRAGMA table_info(tasks)")}
            for name, definition in (("owner", "TEXT NOT NULL DEFAULT ''"),
                                     ("claim_token", "TEXT NOT NULL DEFAULT ''"),
                                     ("lease_until", "REAL"),
                                     ("attempts", "INTEGER NOT NULL DEFAULT 0")):
                if name not in columns:
                    self._db.execute(f"ALTER TABLE tasks ADD COLUMN {name} {definition}")
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
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            current = self.get(run_id)["state"]
            if state != current and state not in RUN_TRANSITIONS[current]:
                raise ValueError(f"invalid run transition: {current} -> {state}")
            if state == "completed" and current != "completed":
                raise ValueError("use finish() to complete a run with its limitations")
            self._db.execute(
                "UPDATE runs SET state=?, updated_at=? WHERE id=?", (state, _now(), run_id)
            )
            self._event(run_id, "run_state", {"state": state})
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
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if self.get(run_id)["state"] not in {"running", "paused"}:
                raise ValueError("cannot add a task to a terminal run")
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

    def update_task(self, task_id: int, state: str, *, result: str = "",
                    owner: str | None = None, claim_token: str | None = None) -> dict:
        if state not in TASK_STATES:
            raise ValueError(f"invalid task state: {state}")
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            task = self.task(task_id)
            if self.get(task["run_id"])["state"] not in {"running", "paused"}:
                raise ValueError("cannot update a task in a terminal run")
            self._validate_owner(task, owner, claim_token)
            if task["state"] in {"completed", "failed", "cancelled"}:
                if state == task["state"] and result == task["result"]:
                    return task
                raise ValueError("terminal task is immutable; use retry_task for failed work")
            if state != task["state"] and state not in TASK_TRANSITIONS[task["state"]]:
                raise ValueError(f"invalid task transition: {task['state']} -> {state}")
            if state in {"running", "completed"} and task["depends_on"] is not None:
                if self.task(task["depends_on"])["state"] != "completed":
                    raise ValueError("task dependency is not completed")
            self._db.execute(
                """UPDATE tasks SET state=?,result=?,updated_at=?,
                   owner=CASE WHEN ?='running' THEN owner ELSE '' END,
                   claim_token=CASE WHEN ?='running' THEN claim_token ELSE '' END,
                   lease_until=CASE WHEN ?='running' THEN lease_until ELSE NULL END WHERE id=?""",
                (state, result, _now(), state, state, state, task_id),
            )
            self._event(task["run_id"], "task_state", {"task_id": task_id, "state": state})
        return self.task(task_id)

    @staticmethod
    def _validate_owner(task: dict, owner: str | None, claim_token: str | None) -> None:
        if task["owner"] or owner or claim_token:
            if owner != task["owner"] or claim_token != task["claim_token"]:
                raise ValueError("task lease owner/token mismatch")
            if task["lease_until"] is None or task["lease_until"] <= time.time():
                raise ValueError("task lease expired; reconcile before retrying")

    @staticmethod
    def _lease_seconds(value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 86400:
            raise ValueError("lease_seconds must be an integer between 1 and 86400")
        return value

    def claim_task(self, run_id: str, owner: str, *, lease_seconds: int = 60,
                   task_id: int | None = None) -> dict | None:
        """Atomically claim one ready task. Expired work is blocked, never replayed."""
        if not owner.strip():
            raise ValueError("task owner is required")
        duration = self._lease_seconds(lease_seconds)
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            run_state = self.get(run_id)["state"]
            if run_state != "running":
                raise ValueError(f"run is {run_state}")
            self._recover_expired(run_id)
            row = self._db.execute(
                """SELECT t.* FROM tasks t LEFT JOIN tasks d ON d.id=t.depends_on
                   WHERE t.run_id=? AND t.state='pending'
                   AND (t.depends_on IS NULL OR d.state='completed')
                   AND (? IS NULL OR t.id=?) ORDER BY t.priority DESC,t.id LIMIT 1""",
                (run_id, task_id, task_id),
            ).fetchone()
            if row is None:
                return None
            token = uuid.uuid4().hex
            self._db.execute("""UPDATE tasks SET state='running',owner=?,claim_token=?,
                lease_until=?,attempts=attempts+1,updated_at=? WHERE id=?""",
                (owner.strip(), token, time.time() + duration, _now(), row["id"]))
            self._event(run_id, "task_claimed", {"task_id": row["id"], "owner": owner.strip()})
            result = self.task(row["id"])
        return result

    def heartbeat(self, task_id: int, owner: str, claim_token: str,
                  *, lease_seconds: int = 60) -> dict:
        duration = self._lease_seconds(lease_seconds)
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            task = self.task(task_id)
            if task["state"] != "running" or self.get(task["run_id"])["state"] != "running":
                raise ValueError("task/run is not running")
            self._validate_owner(task, owner, claim_token)
            self._db.execute("UPDATE tasks SET lease_until=?,updated_at=? WHERE id=?",
                             (time.time() + duration, _now(), task_id))
        return self.task(task_id)

    def _recover_expired(self, run_id: str) -> list[int]:
        rows = self._db.execute("""SELECT id FROM tasks WHERE run_id=? AND state='running'
            AND lease_until IS NOT NULL AND lease_until<=?""", (run_id, time.time())).fetchall()
        ids = [int(row[0]) for row in rows]
        for task_id in ids:
            self._db.execute("""UPDATE tasks SET state='blocked',owner='',claim_token='',
                lease_until=NULL,result=?,updated_at=? WHERE id=?""",
                ("Lease expired; execution outcome is unknown. Reconcile evidence before retry.",
                 _now(), task_id))
            self._db.execute("""UPDATE invocations SET state='unknown',updated_at=?
                WHERE task_id=? AND state='running'""", (_now(), task_id))
            self._event(run_id, "task_lease_expired", {"task_id": task_id})
        return ids

    def recover_expired_tasks(self, run_id: str) -> list[int]:
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            self.get(run_id)
            return self._recover_expired(run_id)

    def retry_task(self, task_id: int, *, reason: str) -> dict:
        """Explicitly retry reconciled blocked/failed work; keep all old receipts."""
        if not reason.strip():
            raise ValueError("retry requires a reconciliation reason")
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            task = self.task(task_id)
            if self.get(task["run_id"])["state"] != "running":
                raise ValueError("run is not running")
            if task["state"] not in {"blocked", "failed"}:
                raise ValueError("only blocked or failed tasks can be retried")
            if self._db.execute("""SELECT 1 FROM invocations i
                LEFT JOIN invocation_resolutions r ON r.invocation_id=i.id
                WHERE i.task_id=? AND (i.state='running'
                    OR (i.state='unknown' AND r.invocation_id IS NULL)) LIMIT 1""",
                                (task_id,)).fetchone():
                raise ValueError("task has an unresolved invocation; reconcile it first")
            self._db.execute("""UPDATE tasks SET state='pending',result=?,owner='',claim_token='',
                lease_until=NULL,updated_at=? WHERE id=?""", (reason.strip(), _now(), task_id))
            self._event(task["run_id"], "task_retry", {"task_id": task_id, "reason": reason.strip()})
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
        if self.get(run_id)["state"] != "running":
            return None
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

    def _reserve(self, run_id: str, *, requests: int = 0, tool_calls: int = 0,
                 intrusive_calls: int = 0) -> None:
        values = {"requests": requests, "tool_calls": tool_calls,
                  "intrusive_calls": intrusive_calls}
        self.get(run_id)
        cur = self._db.execute(
            """UPDATE runs SET requests_used=requests_used+?,
               tool_calls_used=tool_calls_used+?,intrusive_calls_used=intrusive_calls_used+?,
               updated_at=? WHERE id=? AND requests_used+?<=max_requests
               AND tool_calls_used+?<=max_tool_calls
               AND intrusive_calls_used+?<=max_intrusive_calls""",
            (requests, tool_calls, intrusive_calls, _now(), run_id,
             requests, tool_calls, intrusive_calls),
        )
        if cur.rowcount != 1:
            run = self.get(run_id)
            exhausted = [name for name, increment in values.items()
                         if run["budget"][name]["used"] + increment > run["budget"][name]["max"]]
            raise ValueError("budget exceeded: " + ", ".join(exhausted))
        self._event(run_id, "usage", values)

    def begin_invocation(self, run_id: str, tool_name: str, arguments_hash: str, *,
                         task_id: int | None = None, idempotency_key: str | None = None,
                         intrusive: bool = False, owner: str | None = None,
                         claim_token: str | None = None) -> dict:
        """Persist intent and reserve budget together; an existing key never executes again.

        Only a digest of arguments is stored. A running receipt after a crash is
        ambiguous, not permission to replay an operation with possible side effects.
        """
        if not tool_name.strip() or not arguments_hash.strip():
            raise ValueError("tool name and arguments hash are required")
        if idempotency_key is not None and not idempotency_key.strip():
            raise ValueError("idempotency key cannot be empty")
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if idempotency_key is not None:
                existing = self._db.execute(
                    "SELECT id FROM invocations WHERE run_id=? AND idempotency_key=?",
                    (run_id, idempotency_key),
                ).fetchone()
                if existing is not None:
                    record = self.get_invocation(existing[0])
                    if (record["tool_name"] != tool_name or record["arguments_hash"] != arguments_hash
                            or record["task_id"] != task_id or bool(record["intrusive"]) != intrusive):
                        raise ValueError("idempotency key already used for different invocation")
                    return {**record, "created": False}
            run_state = self.get(run_id)["state"]
            if run_state != "running":
                raise ValueError(f"run is {run_state}")
            if task_id is not None:
                task = self.task(task_id)
                if task["run_id"] != run_id:
                    raise ValueError("task must belong to the invocation run")
                if task["state"] != "running":
                    raise ValueError("task is not running")
                self._validate_owner(task, owner, claim_token)
            self._reserve(run_id, tool_calls=1, intrusive_calls=int(intrusive))
            invocation_id, now = uuid.uuid4().hex, _now()
            self._db.execute("""INSERT INTO invocations(id,run_id,task_id,tool_name,
                arguments_hash,idempotency_key,state,intrusive,created_at,updated_at)
                VALUES(?,?,?,?,?,?,'running',?,?,?)""",
                (invocation_id, run_id, task_id, tool_name, arguments_hash, idempotency_key,
                 int(intrusive), now, now))
            self._event(run_id, "invocation_started", {"invocation_id": invocation_id,
                                                       "tool_name": tool_name, "task_id": task_id})
            record = self.get_invocation(invocation_id)
        return {**record, "created": True}

    def get_invocation(self, invocation_id: str) -> dict:
        with self._lock:
            row = self._db.execute("SELECT * FROM invocations WHERE id=?",
                                   (invocation_id,)).fetchone()
        if row is None:
            raise ValueError(f"unknown invocation: {invocation_id}")
        record = dict(row)
        record["result"] = json.loads(record["result"]) if record["result"] is not None else None
        record["resolution"] = self._invocation_resolution(invocation_id)
        return record

    def _invocation_resolution(self, invocation_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM invocation_resolutions WHERE invocation_id=?",
                                   (invocation_id,)).fetchone()
        if row is None:
            return None
        resolution = dict(row)
        resolution["evidence_artifact_ids"] = json.loads(resolution["evidence_artifact_ids"])
        return resolution

    def mark_invocation_unknown(self, invocation_id: str, reason: str) -> dict:
        """Declare an interrupted worker's outcome unknown after stopping its run.

        This is an explicit recovery action, never an inference made on opening
        a database. Stop the previous worker and pause/cancel/fail the run first;
        a live task lease must expire or be released before recovery is accepted.
        """
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
            raise ValueError("recovery requires a reason of 1 to 4000 characters")
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            record = self.get_invocation(invocation_id)
            if record["state"] == "unknown":
                return record
            if record["state"] != "running":
                raise ValueError("only an interrupted running invocation can be marked unknown")
            run_state = self.get(record["run_id"])["state"]
            if run_state not in {"paused", "cancelled", "failed"}:
                raise ValueError("pause, cancel or fail the run before declaring an unknown outcome")
            if record["task_id"] is not None:
                task = self.task(record["task_id"])
                if (task["state"] == "running" and task["lease_until"] is not None
                        and task["lease_until"] > time.time()):
                    raise ValueError("task claim lease is still active; stop the worker and let it expire")
            self._db.execute("UPDATE invocations SET state='unknown',updated_at=? WHERE id=?",
                             (_now(), invocation_id))
            self._event(record["run_id"], "invocation_recovered_unknown", {
                "invocation_id": invocation_id, "reason": reason.strip(), "run_state": run_state,
            })
            return self.get_invocation(invocation_id)

    def reconcile_invocation(self, invocation_id: str, outcome: str, reason: str,
                             evidence_artifact_ids: list[int]) -> dict:
        """Append an evidence-backed resolution without rewriting or replaying a receipt.

        A repeated identical resolution is idempotent; conflicting resolutions
        require a separate review rather than overwriting the historical decision.
        """
        if outcome not in {"completed", "failed", "not_executed"}:
            raise ValueError("reconciliation outcome must be completed, failed or not_executed")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
            raise ValueError("reconciliation requires a reason of 1 to 4000 characters")
        if (not isinstance(evidence_artifact_ids, list) or not evidence_artifact_ids
                or len(evidence_artifact_ids) > 100
                or any(not isinstance(value, int) or isinstance(value, bool) or value < 1
                       for value in evidence_artifact_ids)):
            raise ValueError("reconciliation requires 1 to 100 evidence artifact IDs")
        evidence = sorted(set(evidence_artifact_ids))
        reason = reason.strip()
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            record = self.get_invocation(invocation_id)
            if record["state"] != "unknown":
                raise ValueError("only unknown invocation outcomes can be reconciled")
            for artifact_id in evidence:
                # Verify immutable evidence belongs to exactly this assessment.
                self.get_artifact(record["run_id"], artifact_id)
            previous = record["resolution"]
            if previous is not None:
                if (previous["outcome"] == outcome and previous["reason"] == reason
                        and previous["evidence_artifact_ids"] == evidence):
                    return record
                raise ValueError("invocation resolution is immutable")
            self._db.execute("""INSERT INTO invocation_resolutions
                (invocation_id,outcome,reason,evidence_artifact_ids,created_at) VALUES(?,?,?,?,?)""",
                (invocation_id, outcome, reason, json.dumps(evidence), _now()))
            self._event(record["run_id"], "invocation_reconciled", {
                "invocation_id": invocation_id, "outcome": outcome, "reason": reason,
                "evidence_artifact_ids": evidence,
            })
            return self.get_invocation(invocation_id)

    def check_invocation(self, invocation_id: str) -> dict:
        with self._lock:
            record = self.get_invocation(invocation_id)
            if record["state"] != "running":
                raise ValueError(f"invocation is {record['state']}")
            run_state = self.get(record["run_id"])["state"]
            if run_state != "running":
                raise ValueError(f"run is {run_state}")
            if record["task_id"] is not None:
                task = self.task(record["task_id"])
                if task["state"] != "running":
                    raise ValueError("task is not running")
                if task["lease_until"] is not None and task["lease_until"] <= time.time():
                    raise ValueError("task lease expired; reconcile before retrying")
            return record

    def consume_invocation_request(self, invocation_id: str) -> dict:
        """Reserve one actual HTTP send before dispatch, including redirect hops."""
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            record = self.check_invocation(invocation_id)
            self._reserve(record["run_id"], requests=1)
            self._db.execute("""UPDATE invocations SET requests_used=requests_used+1,
                updated_at=? WHERE id=?""", (_now(), invocation_id))
            return self.get_invocation(invocation_id)

    def finish_invocation(self, invocation_id: str, state: str, result: dict) -> dict:
        """Persist a terminal receipt once; retries can read it but cannot rewrite it."""
        if state not in INVOCATION_STATES - {"running"}:
            raise ValueError(f"invalid invocation outcome: {state}")
        if not isinstance(result, dict):
            raise ValueError("invocation result must be an object")
        encoded = json.dumps(result, sort_keys=True)
        if len(encoded.encode("utf-8")) > 1_000_000:
            raise ValueError("invocation result exceeds the 1 MB limit; store an artifact reference")
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            record = self.get_invocation(invocation_id)
            if record["state"] != "running":
                if record["state"] == state and record["result"] == result:
                    return record
                raise ValueError("invocation already finalized; preserve receipt and reconcile separately")
            self._db.execute("UPDATE invocations SET state=?,result=?,updated_at=? WHERE id=?",
                             (state, encoded, _now(), invocation_id))
            self._event(record["run_id"], "invocation_finished", {"invocation_id": invocation_id,
                                                                 "state": state})
            return self.get_invocation(invocation_id)

    def consume(self, run_id: str, *, requests: int = 0, tool_calls: int = 0,
                intrusive_calls: int = 0) -> dict:
        values = {"requests": requests, "tool_calls": tool_calls,
                  "intrusive_calls": intrusive_calls}
        if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in values.values()):
            raise ValueError("usage increments must be non-negative integers")
        # Commit counters and their event together; roll back on every error,
        # including a rejected UPDATE that still acquires SQLite's write lock.
        with self._lock, self._db:
            self._reserve(run_id, requests=requests, tool_calls=tool_calls,
                          intrusive_calls=intrusive_calls)
        return self.get(run_id)

    def finish(self, run_id: str, *, force: bool = False) -> dict:
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            self._recover_expired(run_id)
            run = self.get(run_id)
            if run["state"] == "completed":
                completed = self._db.execute("""SELECT payload FROM run_events WHERE run_id=?
                    AND kind='run_completed' ORDER BY id DESC LIMIT 1""", (run_id,)).fetchone()
                details = json.loads(completed[0]) if completed else {}
                limitations = details.get("limitations", [])
                return {"completed": True, "run": run, "forced": details.get("forced", False),
                        "blockers": limitations, "limitations": limitations}
            if run["state"] not in {"running", "paused"}:
                raise ValueError("cannot complete a cancelled or failed run")
            blockers = []
            open_tasks = sum(run["tasks"].get(s, 0) for s in ("pending", "running", "blocked"))
            failed_tasks = run["tasks"].get("failed", 0) + run["tasks"].get("cancelled", 0)
            uncovered = sum(run["coverage"]["counts"].get(s, 0) for s in ("open", "in_progress"))
            blocked_coverage = run["coverage"]["counts"].get("blocked", 0)
            if open_tasks:
                blockers.append(f"{open_tasks} unfinished task(s)")
            if failed_tasks:
                blockers.append(f"{failed_tasks} failed/cancelled task(s)")
            if uncovered:
                blockers.append(f"{uncovered} uncovered item(s)")
            if blocked_coverage:
                blockers.append(f"{blocked_coverage} blocked coverage item(s)")
            unresolved = self._db.execute("""SELECT COUNT(*) FROM invocations i
                LEFT JOIN invocation_resolutions r ON r.invocation_id=i.id
                WHERE i.run_id=? AND (i.state='running'
                    OR (i.state='unknown' AND r.invocation_id IS NULL))""", (run_id,)).fetchone()[0]
            if unresolved:
                blockers.append(f"{unresolved} unresolved invocation(s)")
            if blockers and not force:
                return {"completed": False, "run": run, "blockers": blockers,
                        "limitations": blockers,
                        "hint": "reconcile the work or explicitly accept limitations with force=true"}
            if run["state"] != "completed":
                self._db.execute("UPDATE runs SET state='completed',updated_at=? WHERE id=?",
                                 (_now(), run_id))
                self._event(run_id, "run_completed", {"forced": bool(blockers),
                                                      "limitations": blockers})
            return {"completed": True, "run": self.get(run_id), "forced": bool(blockers),
                    "blockers": blockers, "limitations": blockers}

    def brief(self, run_id: str) -> dict:
        """Bounded continuation packet with durable work, evidence and limitations."""
        self.recover_expired_tasks(run_id)
        with self._lock:
            coverage = [dict(row) for row in self._db.execute(
                "SELECT * FROM coverage WHERE run_id=? ORDER BY item", (run_id,))]
            invocations = [dict(row) for row in self._db.execute(
                """SELECT id,task_id,tool_name,state,requests_used,updated_at FROM invocations
                   WHERE run_id=? ORDER BY created_at DESC LIMIT 100""", (run_id,))]
            for invocation in invocations:
                invocation["resolution"] = self._invocation_resolution(invocation["id"])
            completion = self._db.execute("""SELECT payload FROM run_events WHERE run_id=?
                AND kind='run_completed' ORDER BY id DESC LIMIT 1""", (run_id,)).fetchone()
        return {"run": self.get(run_id), "tasks": self.tasks(run_id),
                "next": self.next_task(run_id), "coverage_items": coverage,
                "artifacts": self.artifacts(run_id), "invocations": invocations,
                "limitations": json.loads(completion[0])["limitations"] if completion else [],
                "recovery": "Unknown invocation outcomes require reconciliation; never auto replay."}

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
                "sha256": digest, "size": len(encoded), "created_at": now,
                "uri": f"moonmcp://runs/{run_id}/artifacts/{artifact_id}"}

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

    def get_artifact(self, run_id: str, artifact_id: int) -> dict:
        """Load one run-owned artifact internally (at most the 1 MB write limit).

        Client-facing reads should use ``artifact_read`` for bounded responses.
        """
        if not isinstance(artifact_id, int) or isinstance(artifact_id, bool) or artifact_id < 1:
            raise ValueError("artifact_id must be a positive integer")
        with self._lock:
            row = self._db.execute("SELECT * FROM artifacts WHERE id=? AND run_id=?",
                                   (artifact_id, run_id)).fetchone()
        if row is None:
            raise ValueError(f"unknown artifact {artifact_id} for run {run_id}")
        return {**dict(row), "uri": f"moonmcp://runs/{run_id}/artifacts/{artifact_id}"}

    def artifact_read(self, run_id: str, artifact_id: int, *, offset: int = 0,
                      limit: int = 8192) -> dict:
        """Read one immutable evidence artifact in bounded Unicode character chunks.

        Lookup is by primary key and run, so large artifact collections do not
        hide older/newer records. The digest identifies the complete content;
        offsets count Python Unicode characters, not encoded bytes.
        """
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 65536:
            raise ValueError("limit must be an integer between 1 and 65536 characters")
        result = self.get_artifact(run_id, artifact_id)
        content = result["content"]
        end = min(offset + limit, len(content))
        result.update(content=content[offset:end], offset=offset, limit=limit,
                      total_chars=len(content), next_offset=end if end < len(content) else None,
                      uri=f"moonmcp://runs/{run_id}/artifacts/{artifact_id}")
        return result

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
