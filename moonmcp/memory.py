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

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

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


def normalize_target(target: str | None) -> str:
    """Return the exact IDNA host (or normalized label), never a substring key.

    URL paths, ports and queries remain in the original ``target`` field. Host
    retrieval deliberately groups those URLs, but never includes subdomains.
    """
    value = (target or "").strip()
    if not value:
        return ""
    try:
        return ipaddress.ip_address(value.strip("[]")).compressed.lower()
    except ValueError:
        pass
    try:
        parsed = urlsplit(value if "://" in value or value.startswith("//") else "//" + value)
        host = (parsed.hostname or value).rstrip(".").lower()
        try:
            return ipaddress.ip_address(host).compressed.lower()
        except ValueError:
            pass
        return host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return value.casefold()


def _target_identity(target: str | None) -> str:
    """Dedup equivalent host spelling while retaining case-sensitive URL context."""
    value = (target or "").strip()
    if not value:
        return ""
    try:
        return ipaddress.ip_address(value.strip("[]")).compressed.lower()
    except ValueError:
        pass
    bare = "://" not in value and not value.startswith("//")
    try:
        parsed = urlsplit("//" + value if bare else value)
        host = normalize_target(value)
        authority = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            authority += f":{parsed.port}"
        if "@" in parsed.netloc:
            authority = parsed.netloc.rsplit("@", 1)[0] + "@" + authority
        identity = urlunsplit((parsed.scheme.lower(), authority, parsed.path,
                              parsed.query, parsed.fragment))
        return identity.removeprefix("//") if bare else identity
    except ValueError:
        return value


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
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._fts = False
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._migrate()
            self._fts = self._try_fts()
            self._db.commit()

    def _migrate(self) -> None:
        """Backfill scoped keys and version history once, preserving legacy data."""
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            for table in ("memory", "entities", "relations"):
                columns = {r[1] for r in self._db.execute(f"PRAGMA table_info({table})")}
                for name in ("target_key", "target_identity"):
                    if name not in columns:
                        self._db.execute(
                            f"ALTER TABLE {table} ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
                if "target_key" not in columns or "target_identity" not in columns:
                    for row in self._db.execute(f"SELECT id,target FROM {table}").fetchall():
                        self._db.execute(
                            f"UPDATE {table} SET target_key=?,target_identity=? WHERE id=?",
                            (normalize_target(row["target"]), _target_identity(row["target"]),
                             row["id"]))
                self._db.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{table}_scope "
                    f"ON {table}(target_key,id)")
                if table != "relations" and "revision" not in columns:
                    self._db.execute(
                        f"ALTER TABLE {table} ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_signature "
                "ON memory(kind,target_identity,lower(title))")
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_entities_signature "
                "ON entities(kind,target_identity,lower(name))")
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_relations_signature "
                "ON relations(src,rel,dst,target_identity)")
            self._db.execute("""CREATE TABLE IF NOT EXISTS memory_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_type TEXT NOT NULL,
                item_id INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                trust TEXT NOT NULL,
                accepted INTEGER NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(item_type,item_id,revision)
            )""")
            for table in ("memory", "entities"):
                rows = self._db.execute(
                    f"SELECT t.* FROM {table} t WHERE NOT EXISTS (SELECT 1 FROM "
                    "memory_revisions r WHERE r.item_type=? AND r.item_id=t.id)",
                    (table,)).fetchall()
                for row in rows:
                    self._record_revision(table, int(row["id"]), dict(row), accepted=True)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS memory_metadata (key TEXT PRIMARY KEY,value TEXT)")

    def _try_fts(self) -> bool:
        try:
            self._db.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts "
                "USING fts5(title, body, tags, content='memory', content_rowid='id')")
            # Triggers cover every writer and prevent stale index state on reopen.
            self._db.executescript("""
                CREATE TRIGGER IF NOT EXISTS memory_fts_insert AFTER INSERT ON memory BEGIN
                    INSERT INTO memory_fts(rowid,title,body,tags)
                    VALUES(new.id,new.title,new.body,new.tags);
                END;
                CREATE TRIGGER IF NOT EXISTS memory_fts_delete AFTER DELETE ON memory BEGIN
                    INSERT INTO memory_fts(memory_fts,rowid,title,body,tags)
                    VALUES('delete',old.id,old.title,old.body,old.tags);
                END;
                CREATE TRIGGER IF NOT EXISTS memory_fts_update
                AFTER UPDATE OF title,body,tags ON memory BEGIN
                    INSERT INTO memory_fts(memory_fts,rowid,title,body,tags)
                    VALUES('delete',old.id,old.title,old.body,old.tags);
                    INSERT INTO memory_fts(rowid,title,body,tags)
                    VALUES(new.id,new.title,new.body,new.tags);
                END;
            """)
            if not self._db.execute(
                    "SELECT 1 FROM memory_metadata WHERE key='fts_triggers_v1'").fetchone():
                self._db.execute("INSERT INTO memory_fts(memory_fts) VALUES('rebuild')")
                self._db.execute(
                    "INSERT INTO memory_metadata(key,value) VALUES('fts_triggers_v1','1')")
            return True
        except sqlite3.Error:
            return False

    def _record_revision(self, item_type: str, item_id: int, content: dict,
                         *, accepted: bool) -> int:
        snapshot = {k: v for k, v in content.items()
                    if k not in ("id", "revision", "revision_count", "pending_revisions")}
        encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        content_hash = hashlib.sha256(encoded.encode()).hexdigest()
        previous = self._db.execute(
            "SELECT revision,content_hash,accepted FROM memory_revisions "
            "WHERE item_type=? AND item_id=? ORDER BY revision DESC LIMIT 1",
            (item_type, item_id)).fetchone()
        if (previous is not None and previous["content_hash"] == content_hash
                and bool(previous["accepted"]) == accepted):
            return int(previous["revision"])
        revision = int(previous["revision"]) + 1 if previous is not None else 1
        self._db.execute(
            "INSERT INTO memory_revisions(item_type,item_id,revision,content,content_hash,"
            "trust,accepted,recorded_at) VALUES(?,?,?,?,?,?,?,?)",
            (item_type, item_id, revision, encoded, content_hash, snapshot["trust"], int(accepted),
             datetime.now(timezone.utc).isoformat()))
        return int(revision)

    @staticmethod
    def _select(table: str, alias: str = "m") -> str:
        return (f"{alias}.*, (SELECT COUNT(*) FROM memory_revisions r "
                f"WHERE r.item_type='{table}' AND r.item_id={alias}.id) AS revision_count, "
                f"(SELECT COUNT(*) FROM memory_revisions r WHERE r.item_type='{table}' "
                f"AND r.item_id={alias}.id AND r.accepted=0) AS pending_revisions, "
                f"(SELECT r.content_hash FROM memory_revisions r WHERE r.item_type='{table}' "
                f"AND r.item_id={alias}.id AND r.revision={alias}.revision) AS content_hash")

    @staticmethod
    def _filters(*, target: str | None = None,
                 kind: str | None = None, trust: str | None = None,
                 alias: str = "m") -> tuple[str, list]:
        clauses = ["1=1"]
        values: list = []
        for field, value in (("target_key", normalize_target(target) if target is not None else None),
                             ("kind", kind), ("trust", trust)):
            if value is not None:
                clauses.append(f"{alias}.{field}=?")
                values.append(value)
        return " AND ".join(clauses), values

    # -- mutation ----------------------------------------------------------
    def add(self, *, kind: str, title: str, body: str = "", target: str | None = None,
            severity: str | None = None, source: str = "", trust: str = "untrusted",
            provenance: str = "manual", tags: str = "", session: str = "",
            created_at: str = "") -> int:
        """Store a versioned item. Untrusted updates to curated items are archived
        as pending revisions; the vetted active content is never overwritten.
        Dedup retains URL path/query context; retrieval groups exact target hosts.
        """
        content = dict(kind=str(kind), title=str(title), body=str(body), target=target,
                       target_key=normalize_target(target), target_identity=_target_identity(target),
                       severity=severity, source=str(source), trust=_norm_trust(trust),
                       provenance=_norm_prov(provenance), tags=str(tags), session=str(session),
                       created_at=str(created_at))
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            existing = self._db.execute(
                "SELECT * FROM memory WHERE kind=? AND target_identity=? "
                "AND lower(title)=? ORDER BY id LIMIT 1",
                (content["kind"], content["target_identity"],
                 str(title).lower())).fetchone()
            if existing is not None:
                item_id = int(existing["id"])
                accepted = not (existing["trust"] == "curated" and content["trust"] != "curated")
                if content["severity"] is None:
                    content["severity"] = existing["severity"]
                revision = self._record_revision("memory", item_id, content, accepted=accepted)
                if accepted and revision != existing["revision"]:
                    fields = ",".join(f"{key}=?" for key in content)
                    self._db.execute(f"UPDATE memory SET {fields},revision=? WHERE id=?",
                                     (*content.values(), revision, item_id))
                return item_id
            fields = ",".join(content)
            values = ",".join("?" for _ in content)
            cur = self._db.execute(f"INSERT INTO memory({fields}) VALUES({values})",
                                   tuple(content.values()))
            item_id = int(cur.lastrowid or 0)
            self._record_revision("memory", item_id, content, accepted=True)
            return item_id

    def clear(self, target: str | None = None) -> int:
        """Delete items and history for an exact target identity, or all if omitted.

        Unlike host retrieval, URL deletion does not expand to other paths.
        """
        where = "target_identity=?" if target is not None else "1=1"
        values = [_target_identity(target)] if target is not None else []
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                "DELETE FROM memory_revisions WHERE item_type='memory' AND item_id IN "
                f"(SELECT id FROM memory WHERE {where})", values)
            cur = self._db.execute(f"DELETE FROM memory WHERE {where}", values)
            return cur.rowcount

    # -- querying ----------------------------------------------------------
    def get(self, item_id: int) -> dict | None:
        with self._lock:
            row = self._db.execute(
                f"SELECT {self._select('memory')} FROM memory m WHERE m.id=?",
                (item_id,)).fetchone()
        return dict(row) if row else None

    def revisions(self, item_id: int, *, limit: int = 100) -> list[dict]:
        """Newest versions first, with exact content hashes and applied/current flags."""
        return self._revisions("memory", item_id, limit=limit)

    def entity_revisions(self, entity_id: int, *, limit: int = 100) -> list[dict]:
        return self._revisions("entities", entity_id, limit=limit)

    def _revisions(self, table: str, item_id: int, *, limit: int) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT r.*, r.revision=t.revision AS is_current FROM memory_revisions r "
                f"JOIN {table} t ON t.id=r.item_id WHERE r.item_type=? AND r.item_id=? "
                "ORDER BY r.revision DESC LIMIT ?",
                (table, item_id, max(1, min(limit, 1000)))).fetchall()
        return [{**dict(row), "content": json.loads(row["content"]),
                 "accepted": bool(row["accepted"]), "is_current": bool(row["is_current"])}
                for row in rows]

    def search(self, query: str, *, kind: str | None = None, trust: str | None = None,
               target: str | None = None, limit: int = 20) -> list[dict]:
        """Search active versions with SQL scope/trust filters applied before LIMIT.

        A target URL matches its exact normalized host, preserving each result's
        original URL.
        """
        limit = max(1, min(limit, 200))
        q = (query or "").strip()
        where, values = self._filters(target=target, kind=kind, trust=trust)
        select = self._select("memory")
        with self._lock:
            if not q:
                rows = self._db.execute(
                    f"SELECT {select} FROM memory m WHERE {where} ORDER BY m.id DESC LIMIT ?",
                    (*values, limit)).fetchall()
                return [dict(row) for row in rows]
            if self._fts:
                try:
                    rows = self._db.execute(
                        f"SELECT {select} FROM memory_fts f JOIN memory m ON m.id=f.rowid "
                        f"WHERE memory_fts MATCH ? AND {where} "
                        "ORDER BY bm25(memory_fts),m.id DESC LIMIT ?",
                        (_fts_query(q), *values, limit)).fetchall()
                    return [dict(row) for row in rows]
                except sqlite3.Error:
                    pass
            like = f"%{q}%"
            rows = self._db.execute(
                f"SELECT {select} FROM memory m WHERE "
                f"(m.title LIKE ? OR m.body LIKE ? OR m.tags LIKE ?) AND {where} "
                "ORDER BY m.id DESC LIMIT ?", (like, like, like, *values, limit)).fetchall()
            return [dict(row) for row in rows]

    def recent(self, limit: int = 50, kind: str | None = None) -> list[dict]:
        where, values = self._filters(kind=kind)
        with self._lock:
            rows = self._db.execute(
                f"SELECT {self._select('memory')} FROM memory m WHERE {where} "
                "ORDER BY m.id DESC LIMIT ?", (*values, max(1, min(limit, 500)))).fetchall()
        return [dict(row) for row in rows]

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
        """Upsert an entity. Untrusted attrs never overwrite curated attributes;
        proposed versions remain available through ``entity_revisions``.
        """
        k = (kind or "").strip().lower() or "asset"
        nm = (name or "").strip()
        if not nm:
            return 0
        content = dict(kind=k, name=nm, target=target, target_key=normalize_target(target),
                       target_identity=_target_identity(target), attrs=str(attrs),
                       trust=_norm_trust(trust), created_at="")
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "SELECT * FROM entities WHERE kind=? AND lower(name)=? "
                "AND target_identity=? ORDER BY id LIMIT 1",
                (k, nm.lower(), content["target_identity"])).fetchone()
            if row is not None:
                entity_id = int(row["id"])
                accepted = not (row["trust"] == "curated" and content["trust"] != "curated")
                if not content["attrs"]:
                    content["attrs"] = row["attrs"]
                revision = self._record_revision("entities", entity_id, content, accepted=accepted)
                if accepted and revision != row["revision"]:
                    fields = ",".join(f"{key}=?" for key in content)
                    self._db.execute(f"UPDATE entities SET {fields},revision=? WHERE id=?",
                                     (*content.values(), revision, entity_id))
                return entity_id
            fields, values = ",".join(content), ",".join("?" for _ in content)
            cur = self._db.execute(f"INSERT INTO entities({fields}) VALUES({values})",
                                   tuple(content.values()))
            entity_id = int(cur.lastrowid or 0)
            self._record_revision("entities", entity_id, content, accepted=True)
            return entity_id

    def add_relation(self, src: str, rel: str, dst: str, *, target: str | None = None) -> int:
        """Add a typed edge scoped to an exact target identity."""
        s, r, d = (src or "").strip(), (rel or "").strip().lower(), (dst or "").strip()
        if not (s and r and d):
            return 0
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "SELECT id FROM relations WHERE src=? AND rel=? AND dst=? "
                "AND target_identity=? LIMIT 1",
                (s, r, d, _target_identity(target))).fetchone()
            if row is not None:
                return int(row["id"])
            cur = self._db.execute(
                "INSERT INTO relations(src,rel,dst,target,created_at,target_key,target_identity) "
                "VALUES(?,?,?,?,?,?,?)",
                (s, r, d, target, "", normalize_target(target), _target_identity(target)))
            return int(cur.lastrowid or 0)

    def entities(self, *, target: str | None = None, kind: str | None = None,
                 limit: int = 200) -> list[dict]:
        where, values = self._filters(target=target,
                                      kind=kind.strip().lower() if kind else None)
        with self._lock:
            rows = self._db.execute(
                f"SELECT {self._select('entities')} FROM entities m WHERE {where} "
                "ORDER BY m.id DESC LIMIT ?", (*values, max(1, min(limit, 1000)))).fetchall()
        return [dict(row) for row in rows]

    def graph(self, target: str | None = None, *, limit: int = 500) -> dict:
        """The entity + relation subgraph for an exact target host."""
        limit = max(1, min(limit, 1000))
        ents = self.entities(target=target, limit=limit)
        where, values = self._filters(target=target)
        with self._lock:
            rows = self._db.execute(
                f"SELECT m.* FROM relations m WHERE {where} ORDER BY m.id DESC LIMIT ?",
                (*values, limit)).fetchall()
        return {"target": target, "entities": ents,
                "relations": [{"src": row["src"], "rel": row["rel"], "dst": row["dst"]}
                              for row in rows]}

    def brief(self, target: str) -> dict:
        """Bounded host summary, with exact counts and cross-target lessons.

        Filters run before LIMIT; unrelated history cannot hide older findings.
        Summary results preserve IDs, original URLs and content revision metadata.
        """
        host = normalize_target(target)
        g = self.graph(host)
        by_kind: dict[str, list[str]] = {}
        for entity in g["entities"]:
            by_kind.setdefault(entity["kind"], []).append(entity["name"])
        with self._lock:
            rows = self._db.execute(
                "SELECT kind,COUNT(*) AS n FROM memory WHERE target_key=? "
                "GROUP BY kind", (host,)).fetchall()
            counts = {r["kind"]: int(r["n"]) for r in rows}
            entity_count = self._db.execute(
                "SELECT COUNT(*) FROM entities WHERE target_key=?",
                (host,)).fetchone()[0]
            relation_count = self._db.execute(
                "SELECT COUNT(*) FROM relations WHERE target_key=?",
                (host,)).fetchone()[0]
        findings = sorted(
            [item for kind in ("finding", "vuln")
             for item in self.search("", kind=kind, target=host, limit=50)],
            key=lambda item: item["id"], reverse=True)[:50]
        leads = sorted(
            [item for kind in ("lead", "observation")
             for item in self.search("", kind=kind, target=host, limit=50)],
            key=lambda item: item["id"], reverse=True)[:50]
        lessons = self.search("", kind="lesson", limit=20)
        return {
            "target": target,
            "entities": {k: sorted(set(v)) for k, v in by_kind.items()},
            "findings": [{key: item[key] for key in
                          ("id", "title", "target", "severity", "trust", "revision",
                           "revision_count", "pending_revisions")} for item in findings],
            "leads": [item["title"] for item in leads],
            "lead_items": [{key: item[key] for key in
                            ("id", "title", "target", "trust", "revision")} for item in leads],
            "lessons": [{"title": item["title"], "body": item["body"][:200],
                         "trust": item["trust"]} for item in lessons],
            "relation_count": relation_count,
            "counts": {"entities": entity_count,
                       "findings": counts.get("finding", 0) + counts.get("vuln", 0),
                       "leads": counts.get("lead", 0) + counts.get("observation", 0)},
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

    terms = re.findall(r"[^\W_]+", q, flags=re.UNICODE)
    if not terms:
        return '""'
    return " OR ".join(f"{t}*" for t in terms)
