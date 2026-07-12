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
# Entity kinds for the structured knowledge graph (see add_entity / graph).
ENTITY_KINDS = ("host", "endpoint", "param", "technology", "service", "cve", "credential", "asset")
# Relation verbs connecting two graph nodes (entities or `finding:<memory_id>`).
RELATIONS = ("affects", "on", "uses", "exposes", "caused_by", "related_to", "confirms", "hosts")

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

-- Structured knowledge graph: typed entities + typed relations, so findings are
-- more than flat notes — a host has endpoints, an endpoint has params, a finding
-- AFFECTS a host, a vuln is CAUSED_BY a root cause, etc.
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    target TEXT,
    attrs TEXT NOT NULL DEFAULT '',
    trust TEXT NOT NULL DEFAULT 'untrusted',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_entities_target ON entities(target);
CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);

CREATE TABLE IF NOT EXISTS relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src TEXT NOT NULL,
    rel TEXT NOT NULL,
    dst TEXT NOT NULL,
    target TEXT,
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target);
CREATE INDEX IF NOT EXISTS idx_relations_src ON relations(src);
CREATE INDEX IF NOT EXISTS idx_relations_dst ON relations(dst);
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
            # Dedup/upsert on an exact content signature (kind + target + title). The
            # store is persistent and write-heavy (every add_finding/promote_lead/
            # confirm_finding mirrors here), so re-running a target would otherwise fill
            # it with near-identical rows and drown retrieval. An exact-signature match
            # folds the new body/source into the existing row instead of inserting.
            existing = self._db.execute(
                "SELECT id FROM memory WHERE kind=? AND lower(COALESCE(target,''))=? "
                "AND lower(title)=? ORDER BY id LIMIT 1",
                (str(kind), (target or "").lower(), str(title).lower()),
            ).fetchone()
            if existing is not None:
                existing_id = int(existing["id"])
                if self._fts:  # remove the stale FTS entry using its CURRENT stored values
                    self._db.execute(
                        "INSERT INTO memory_fts(memory_fts,rowid,title,body,tags) "
                        "SELECT 'delete', id, title, body, tags FROM memory WHERE id=?", (existing_id,))
                self._db.execute(
                    "UPDATE memory SET body=?, severity=COALESCE(?,severity), source=?, "
                    "trust=CASE WHEN trust='curated' THEN 'curated' ELSE ? END, "
                    "provenance=?, tags=?, session=?, created_at=? WHERE id=?",
                    (str(body), severity, str(source), _norm_trust(trust), _norm_prov(provenance),
                     str(tags), str(session), str(created_at), existing_id))
                if self._fts:
                    self._db.execute(
                        "INSERT INTO memory_fts(rowid,title,body,tags) VALUES(?,?,?,?)",
                        (existing_id, str(title), str(body), str(tags)))
                self._db.commit()
                return existing_id
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

    # -- knowledge graph ---------------------------------------------------
    def add_entity(self, *, kind: str, name: str, target: str | None = None,
                   attrs: str = "", trust: str = "untrusted") -> int:
        """Upsert a typed graph entity (host / endpoint / param / technology / …).
        Dedups on (kind, name, target) case-insensitively; merges attrs and never
        downgrades curated trust. Returns the entity id (0 for a blank name)."""

        k = (kind or "").strip().lower() or "asset"
        nm = (name or "").strip()
        if not nm:
            return 0
        with self._lock:
            row = self._db.execute(
                "SELECT id FROM entities WHERE kind=? AND lower(name)=? "
                "AND lower(COALESCE(target,''))=? ORDER BY id LIMIT 1",
                (k, nm.lower(), (target or "").lower())).fetchone()
            if row is not None:
                eid = int(row["id"])
                self._db.execute(
                    "UPDATE entities SET attrs=CASE WHEN ?<>'' THEN ? ELSE attrs END, "
                    "trust=CASE WHEN trust='curated' THEN 'curated' ELSE ? END WHERE id=?",
                    (str(attrs), str(attrs), _norm_trust(trust), eid))
                self._db.commit()
                return eid
            cur = self._db.execute(
                "INSERT INTO entities(kind,name,target,attrs,trust,created_at) VALUES(?,?,?,?,?,?)",
                (k, nm, target, str(attrs), _norm_trust(trust), ""))
            self._db.commit()
            return int(cur.lastrowid or 0)

    def add_relation(self, src: str, rel: str, dst: str, *, target: str | None = None) -> int:
        """Add a typed edge between two nodes (an entity key ``kind:name`` or a
        ``finding:<memory_id>``). Dedups on (src, rel, dst, target)."""

        s, r, d = (src or "").strip(), (rel or "").strip().lower(), (dst or "").strip()
        if not (s and r and d):
            return 0
        with self._lock:
            row = self._db.execute(
                "SELECT id FROM relations WHERE src=? AND rel=? AND dst=? "
                "AND lower(COALESCE(target,''))=? LIMIT 1",
                (s, r, d, (target or "").lower())).fetchone()
            if row is not None:
                return int(row["id"])
            cur = self._db.execute(
                "INSERT INTO relations(src,rel,dst,target,created_at) VALUES(?,?,?,?,?)",
                (s, r, d, target, ""))
            self._db.commit()
            return int(cur.lastrowid or 0)

    def entities(self, *, target: str | None = None, kind: str | None = None,
                 limit: int = 200) -> list[dict]:
        limit = max(1, min(limit, 1000))
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM entities ORDER BY id DESC LIMIT ?", (limit * 4,)).fetchall()
        out = []
        for row in rows:
            e = dict(row)
            if target and (e.get("target") or "").lower() != target.lower():
                continue
            if kind and e["kind"] != kind.strip().lower():
                continue
            out.append(e)
        return out[:limit]

    def graph(self, target: str | None = None, *, limit: int = 500) -> dict:
        """The entity + relation subgraph for *target* (everything if None)."""

        ents = self.entities(target=target, limit=limit)
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM relations ORDER BY id DESC LIMIT ?", (limit * 4,)).fetchall()
        rels = []
        for row in rows:
            d = dict(row)
            if target and (d.get("target") or "").lower() != target.lower():
                continue
            rels.append({"src": d["src"], "rel": d["rel"], "dst": d["dst"]})
        return {"target": target, "entities": ents, "relations": rels[:limit]}

    def brief(self, target: str) -> dict:
        """One-shot *what we know about TARGET*: entities grouped by kind, confirmed
        findings, open leads, cross-target lessons, and the relation count. ``target``
        should be a host — graph nodes are host-keyed, while memory items (recorded
        under a full URL) are matched by host substring so both surface."""

        host = (target or "").strip().lower()
        g = self.graph(host)
        by_kind: dict[str, list[str]] = {}
        for e in g["entities"]:
            by_kind.setdefault(e["kind"], []).append(e["name"])
        pool = self.search("", limit=400)
        items = [i for i in pool if host and host in (i.get("target") or "").lower()] if host else pool
        findings = [i for i in items if i["kind"] in ("finding", "vuln")]
        leads = [i for i in items if i["kind"] in ("lead", "observation")]
        lessons = self.search("", kind="lesson", limit=50)
        return {
            "target": target,
            "entities": {k: sorted(set(v)) for k, v in by_kind.items()},
            "findings": [{"title": f["title"], "severity": f.get("severity"), "trust": f["trust"]}
                         for f in findings[:50]],
            "leads": [x["title"] for x in leads[:50]],
            "lessons": [{"title": x["title"], "body": x["body"][:200]} for x in lessons[:20]],
            "relation_count": len(g["relations"]),
            "counts": {"entities": len(g["entities"]), "findings": len(findings),
                       "leads": len(leads)},
        }

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
