"""Shared, persistent memory hub — the substrate a multi-agent org talks to.

A single SQLite store (stdlib ``sqlite3``, no dependency) that outlives one
session and can be shared by every agent in a chain — the orchestrator, a
delegated validator (e.g. Strix), and a local librarian/curator. It holds
recon observations, findings and curated knowledge as searchable "memory items",
so agents stop re-deriving context and can build on each other's work.

Two disciplines are baked in:

* **Provenance + trust on every item.** Each item carries ``trust`` —
  ``untrusted`` (scraped/observed content: response bodies, third-party PoCs,
  anything a target served) vs ``curated`` (a vetted finding/note an operator or
  agent asserted) — and ``provenance`` (``extracted`` / ``inferred`` /
  ``manual``). This is the anti-**poisoning** guard: untrusted content is stored
  *labeled*, retrieval can filter by trust, and untrusted items must never be
  treated as instructions.
* **Full-text search** via SQLite FTS5 (bm25-ranked) when the build supports it,
  with a plain ``LIKE`` fallback otherwise — so ``memory_search`` works anywhere.

Persists to ``MOONMCP_STATE_DIR/memory.db`` when set, else an in-memory DB (still
fully functional for the session).
"""

from __future__ import annotations

import os
import sqlite3
import threading

TRUST = ("untrusted", "curated")
PROVENANCE = ("extracted", "inferred", "manual")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    target TEXT,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    severity TEXT,
    source TEXT NOT NULL DEFAULT '',
    trust TEXT NOT NULL DEFAULT 'untrusted',
    provenance TEXT NOT NULL DEFAULT 'manual',
    tags TEXT NOT NULL DEFAULT '',
    session TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_memory_target ON memory(target);
CREATE INDEX IF NOT EXISTS idx_memory_kind ON memory(kind);
CREATE INDEX IF NOT EXISTS idx_memory_trust ON memory(trust);
"""


def _norm_trust(v: str | None) -> str:
    v = (v or "untrusted").strip().lower()
    return v if v in TRUST else "untrusted"


def _norm_prov(v: str | None) -> str:
    v = (v or "manual").strip().lower()
    return v if v in PROVENANCE else "manual"


class MemoryStore:
    """A shared, persistent, searchable memory (SQLite + optional FTS5)."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or ":memory:"
        # check_same_thread=False + a lock so it is safe if a tool ever runs off
        # the event-loop thread; all ops are fast local reads/writes.
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._fts = False
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._fts = self._try_fts()
            self._db.commit()

    def _try_fts(self) -> bool:
        try:
            self._db.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts "
                "USING fts5(title, body, tags, content='memory', content_rowid='id')"
            )
            # Backfill if the table pre-existed without FTS being populated.
            self._db.execute(
                "INSERT INTO memory_fts(memory_fts) VALUES('rebuild')"
            )
            return True
        except sqlite3.Error:
            return False

    # -- mutation ----------------------------------------------------------
    def add(self, *, kind: str, title: str, body: str = "", target: str | None = None,
            severity: str | None = None, source: str = "", trust: str = "untrusted",
            provenance: str = "manual", tags: str = "", session: str = "",
            created_at: str = "") -> int:
        """Store a memory item; returns its id. ``trust`` defaults to *untrusted*
        (safe default for observed/scraped content) — pass ``curated`` only for
        vetted knowledge."""

        with self._lock:
            cur = self._db.execute(
                "INSERT INTO memory(kind,target,title,body,severity,source,trust,"
                "provenance,tags,session,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (str(kind), target, str(title), str(body), severity, str(source),
                 _norm_trust(trust), _norm_prov(provenance), str(tags), str(session),
                 str(created_at)),
            )
            rowid = cur.lastrowid
            if self._fts and rowid is not None:
                self._db.execute(
                    "INSERT INTO memory_fts(rowid,title,body,tags) VALUES(?,?,?,?)",
                    (rowid, str(title), str(body), str(tags)),
                )
            self._db.commit()
            return int(rowid or 0)

    def clear(self, target: str | None = None) -> int:
        with self._lock:
            if target is None:
                n = self._db.execute("SELECT COUNT(*) FROM memory").fetchone()[0]
                self._db.execute("DELETE FROM memory")
                if self._fts:
                    self._db.execute("INSERT INTO memory_fts(memory_fts) VALUES('delete-all')")
            else:
                rows = self._db.execute("SELECT id FROM memory WHERE target=?", (target,)).fetchall()
                n = len(rows)
                if self._fts:
                    for r in rows:
                        self._db.execute(
                            "INSERT INTO memory_fts(memory_fts,rowid,title,body,tags) "
                            "SELECT 'delete', id, title, body, tags FROM memory WHERE id=?",
                            (r["id"],),
                        )
                self._db.execute("DELETE FROM memory WHERE target=?", (target,))
            self._db.commit()
            return int(n)

    # -- querying ----------------------------------------------------------
    def get(self, item_id: int) -> dict | None:
        with self._lock:  # the shared connection is used under the lock everywhere else
            row = self._db.execute("SELECT * FROM memory WHERE id=?", (item_id,)).fetchone()
        return dict(row) if row else None

    def _filtered(self, rows: list, *, kind: str | None, trust: str | None,
                  target: str | None) -> list[dict]:
        out = []
        for r in rows:
            d = dict(r)
            if kind and d["kind"] != kind:
                continue
            if trust and d["trust"] != trust:
                continue
            if target and (d.get("target") or "").lower() != target.lower():
                continue
            out.append(d)
        return out

    def search(self, query: str, *, kind: str | None = None, trust: str | None = None,
               target: str | None = None, limit: int = 20) -> list[dict]:
        """Full-text search (bm25-ranked via FTS5, else LIKE). Empty query returns
        the most recent items. Every hit carries its ``trust`` label."""

        limit = max(1, min(limit, 200))
        q = (query or "").strip()
        with self._lock:
            if not q:
                rows = self._db.execute(
                    "SELECT * FROM memory ORDER BY id DESC LIMIT ?", (limit * 4,)
                ).fetchall()
                return self._filtered(rows, kind=kind, trust=trust, target=target)[:limit]
            if self._fts:
                try:
                    rows = self._db.execute(
                        "SELECT m.* FROM memory_fts f JOIN memory m ON m.id=f.rowid "
                        "WHERE memory_fts MATCH ? ORDER BY bm25(memory_fts) LIMIT ?",
                        (_fts_query(q), limit * 4),
                    ).fetchall()
                    return self._filtered(rows, kind=kind, trust=trust, target=target)[:limit]
                except sqlite3.Error:
                    pass  # malformed FTS query → fall back to LIKE
            like = f"%{q}%"
            rows = self._db.execute(
                "SELECT * FROM memory WHERE title LIKE ? OR body LIKE ? OR tags LIKE ? "
                "ORDER BY id DESC LIMIT ?", (like, like, like, limit * 4),
            ).fetchall()
            return self._filtered(rows, kind=kind, trust=trust, target=target)[:limit]

    def recent(self, limit: int = 50, kind: str | None = None) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM memory ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)
            ).fetchall()
        return [dict(r) for r in rows if not kind or dict(r)["kind"] == kind]

    def stats(self) -> dict:
        with self._lock:
            total = self._db.execute("SELECT COUNT(*) FROM memory").fetchone()[0]
            by_kind = {r[0]: r[1] for r in self._db.execute(
                "SELECT kind, COUNT(*) FROM memory GROUP BY kind").fetchall()}
            by_trust = {r[0]: r[1] for r in self._db.execute(
                "SELECT trust, COUNT(*) FROM memory GROUP BY trust").fetchall()}
        return {"total": total, "fts": self._fts, "db": self.db_path,
                "by_kind": by_kind, "by_trust": by_trust}

    def close(self) -> None:
        try:
            self._db.close()
        except sqlite3.Error:
            pass

    @classmethod
    def from_env(cls) -> MemoryStore:
        state = os.environ.get("MOONMCP_STATE_DIR")
        if state:
            try:
                os.makedirs(state, exist_ok=True)
                return cls(db_path=os.path.join(state, "memory.db"))
            except OSError:
                pass
        return cls()


def _fts_query(q: str) -> str:
    """Turn free text into a safe FTS5 MATCH query: each bareword becomes a
    prefix term, OR-joined, so partial words still hit and punctuation can't
    break the query syntax."""

    import re

    terms = re.findall(r"[A-Za-z0-9_]+", q)
    if not terms:
        return '""'
    return " OR ".join(f"{t}*" for t in terms)
