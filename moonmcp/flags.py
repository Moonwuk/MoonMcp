"""Persistent observations and evidence-backed hypotheses, without automatic findings.

The tables may share memory.db, but never inherit trust from the legacy memory
upsert path. Facts and their original evidence are immutable; reviews are events.
Project boundaries are mandatory, including when two projects share a hostname.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

FLAG_STATES = {"new", "reviewed", "refuted", "stale"}
HYPOTHESIS_STATES = {"proposed", "testing", "supported", "refuted", "inconclusive", "stale"}
IMPORTANCE = {"unknown", "low", "medium", "high"}


class EvidenceRef(BaseModel):
    """A source locator, not an instruction or an assertion of independent proof."""

    ref: str = Field(min_length=1, max_length=2000)
    source_group: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=2000)
    content_hash: str = Field(default="", max_length=64)


def _text(value: str, name: str, limit: int = 4000, *, required: bool = True) -> str:
    value = value.strip()
    if (required and not value) or len(value) > limit:
        raise ValueError(f"{name} must contain {'1' if required else '0'}..{limit} characters")
    return value


def target_key(target: str) -> str:
    """Exact host identity; paths and role context remain on the observation."""
    target = _text(target, "target", 2000)
    try:
        return ipaddress.ip_address(target.strip("[]")).compressed
    except ValueError:
        pass
    parsed = urlsplit(target if "://" in target else "//" + target)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("target must be a hostname, IP, or URL without credentials")
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise ValueError("target URL must use http or https")
    host = parsed.hostname.rstrip(".")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            canonical = host.encode("idna").decode("ascii").casefold()
        except UnicodeError as exc:
            raise ValueError("invalid target hostname") from exc
        if len(canonical) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in canonical.split(".")
        ):
            raise ValueError("invalid target hostname") from None
        return canonical


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _date(value: str, name: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _evidence(values: list[EvidenceRef | dict], *, required: bool = True) -> list[dict]:
    if len(values) > 50 or (required and not values):
        raise ValueError("provide 1..50 evidence references" if required else "at most 50 evidence references")
    result = []
    for item in values:
        ref = item if isinstance(item, EvidenceRef) else EvidenceRef.model_validate(item)
        data = ref.model_dump()
        data["ref"] = _text(data["ref"], "evidence ref", 2000)
        data["source_group"] = _text(data["source_group"], "source_group", 300)
        digest = data["content_hash"]
        if digest and (len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest)):
            raise ValueError("content_hash must be a SHA-256 hex digest")
        data["content_hash"] = digest.lower()
        if data not in result:
            result.append(data)
    return result


def _strings(values: list[str] | None, name: str, *, fold: bool = False) -> list[str]:
    if values is None:
        return []
    if len(values) > 50:
        raise ValueError(f"{name} accepts at most 50 entries")
    normalized = [_text(v, name, 300) for v in values]
    return sorted({v.casefold() if fold else v for v in normalized})


_SCHEMA = """
CREATE TABLE IF NOT EXISTS observation_flags (
    id TEXT PRIMARY KEY, project TEXT NOT NULL, target TEXT NOT NULL,
    target_key TEXT NOT NULL, observation TEXT NOT NULL, evidence TEXT NOT NULL,
    observation_kind TEXT NOT NULL, importance TEXT NOT NULL, auth_context TEXT NOT NULL,
    entities TEXT NOT NULL, tags TEXT NOT NULL, run_id TEXT NOT NULL,
    next_check TEXT NOT NULL, status TEXT NOT NULL, observed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    fingerprint TEXT NOT NULL, search_text TEXT NOT NULL,
    UNIQUE(project, fingerprint)
);
CREATE INDEX IF NOT EXISTS flags_target ON observation_flags(project,target_key,created_at);
CREATE TABLE IF NOT EXISTS flag_context_terms (
    flag_id TEXT NOT NULL REFERENCES observation_flags(id), project TEXT NOT NULL,
    term TEXT NOT NULL, PRIMARY KEY(flag_id,term)
);
CREATE INDEX IF NOT EXISTS flag_context_lookup ON flag_context_terms(project,term);
CREATE TABLE IF NOT EXISTS flag_relations (
    src TEXT NOT NULL REFERENCES observation_flags(id),
    dst TEXT NOT NULL REFERENCES observation_flags(id),
    relation TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(src,dst,relation)
);
CREATE TABLE IF NOT EXISTS analysis_hypotheses (
    id TEXT PRIMARY KEY, project TEXT NOT NULL, target TEXT NOT NULL, target_key TEXT NOT NULL,
    claim TEXT NOT NULL, alternatives TEXT NOT NULL, test_plan TEXT NOT NULL,
    expected_observation TEXT NOT NULL, run_id TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS hypothesis_target ON analysis_hypotheses(project,target_key,created_at);
CREATE TABLE IF NOT EXISTS hypothesis_flags (
    hypothesis_id TEXT NOT NULL REFERENCES analysis_hypotheses(id),
    flag_id TEXT NOT NULL REFERENCES observation_flags(id),
    relation TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(hypothesis_id,flag_id,relation)
);
CREATE TABLE IF NOT EXISTS analysis_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL,
    object_id TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS analysis_event_object ON analysis_events(project,object_id,id);
"""


class FlagStore:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or ":memory:"
        self._db = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def _event(self, project: str, object_id: str, kind: str, detail: dict) -> None:
        self._db.execute(
            "INSERT INTO analysis_events(project,object_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
            (project, object_id, kind, _json(detail), _now()),
        )

    def _row(self, table: str, project: str, object_id: str) -> dict:
        if table not in {"observation_flags", "analysis_hypotheses"}:
            raise ValueError("unknown object type")
        row = self._db.execute(f"SELECT * FROM {table} WHERE project=? AND id=?",  # noqa: S608
                               (_text(project, "project", 300), object_id)).fetchone()
        if row is None:
            raise ValueError("unknown analysis object in this project")
        result = dict(row)
        for field in ("evidence", "entities", "tags", "alternatives"):
            if field in result:
                result[field] = json.loads(result[field])
        result.pop("search_text", None)
        result.pop("fingerprint", None)
        if table == "observation_flags":
            result["effective_status"] = (
                "stale" if result["expires_at"] and result["expires_at"] <= _now()
                and result["status"] not in {"refuted", "stale"} else result["status"])
            result["trust"] = "untrusted"
        return result

    def record(self, project: str, target: str, observation: str,
               evidence: list[EvidenceRef | dict], *, observation_kind: str = "direct",
               importance: str = "unknown", auth_context: str = "",
               entities: list[str] | None = None, tags: list[str] | None = None,
               run_id: str = "", next_check: str = "", observed_at: str = "",
               expires_at: str = "") -> dict:
        project = _text(project, "project", 300)
        target = _text(target, "target", 2000)
        observation = _text(observation, "observation")
        host = target_key(target)
        if observation_kind not in {"direct", "inferred", "reported"}:
            raise ValueError("observation_kind must be direct, inferred or reported")
        if importance not in IMPORTANCE:
            raise ValueError("importance must be unknown, low, medium or high")
        refs = _evidence(evidence)
        entity_list, tag_list = _strings(entities, "entities"), _strings(tags, "tags", fold=True)
        auth_context = _text(auth_context, "auth_context", 300, required=False)
        run_id = _text(run_id, "run_id", 100, required=False)
        next_check = _text(next_check, "next_check", required=False)
        observed = _date(observed_at, "observed_at") if observed_at else _now()
        expires = _date(expires_at, "expires_at") if expires_at else ""
        if expires and expires <= observed:
            raise ValueError("expires_at must be later than observed_at")
        # Identical retries reuse an observation. A new source or explicit time
        # creates a new flag, preserving repeated observations over time.
        signature = [target, observation, refs, observation_kind, auth_context,
                     entity_list, tag_list, run_id, observed if observed_at else "", expires]
        fingerprint = hashlib.sha256(_json(signature).encode()).hexdigest()
        now, flag_id = _now(), "flag_" + uuid.uuid4().hex
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            existing = self._db.execute(
                "SELECT id FROM observation_flags WHERE project=? AND fingerprint=?",
                (project, fingerprint),
            ).fetchone()
            if existing:
                return {"flag": self._row("observation_flags", project, existing["id"]),
                        "created": False, "related": self.related(project, existing["id"])}
            self._db.execute(
                "INSERT INTO observation_flags VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (flag_id, project, target, host, observation, _json(refs), observation_kind,
                 importance, auth_context, _json(entity_list), _json(tag_list), run_id,
                 next_check, "new", observed, expires, now, now, fingerprint,
                 " ".join([observation, *entity_list, *tag_list, next_check]).casefold()),
            )
            self._event(project, flag_id, "recorded", {"evidence": refs})
            self._db.executemany("INSERT INTO flag_context_terms VALUES(?,?,?)",
                                 [(flag_id, project, term) for term in self._terms(
                                     {"target_key": host, "entities": entity_list,
                                      "tags": tag_list, "evidence": refs})])
        return {"flag": self.get(project, flag_id), "created": True,
                "related": self.related(project, flag_id)}

    def get(self, project: str, flag_id: str, *, include_history: bool = False) -> dict:
        project = _text(project, "project", 300)
        with self._lock:
            result = self._row("observation_flags", project, flag_id)
            result["links"] = [dict(r) for r in self._db.execute(
                "SELECT src,dst,relation,reason,active FROM flag_relations WHERE src=? OR dst=?",
                (flag_id, flag_id))]
            result["hypotheses"] = [dict(r) for r in self._db.execute(
                "SELECT hypothesis_id,relation,reason,active FROM hypothesis_flags WHERE flag_id=?", (flag_id,))]
            if include_history:
                result["history"] = self.history(project, flag_id)
            return result

    def history(self, project: str, object_id: str) -> list[dict]:
        project = _text(project, "project", 300)
        with self._lock:
            return [{**dict(r), "detail": json.loads(r["detail"])} for r in self._db.execute(
                "SELECT id,kind,detail,created_at FROM analysis_events WHERE project=? AND object_id=? ORDER BY id",
                (project, object_id))]

    def query(self, project: str, *, target: str = "", query: str = "", status: str = "",
              run_id: str = "", limit: int = 20, offset: int = 0) -> dict:
        project = _text(project, "project", 300)
        if status and status not in FLAG_STATES:
            raise ValueError("invalid flag status")
        if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise ValueError("limit must be 1..100; offset must be 0..100000")
        conditions, args = ["project=?"], [project]
        if target:
            conditions.append("target_key=?")
            args.append(target_key(target))
        if run_id:
            conditions.append("run_id=?")
            args.append(run_id)
        # Filtering and temporal status are evaluated before pagination.
        if status == "stale":
            conditions.append("(status='stale' OR (expires_at<>'' AND expires_at<=? AND status<>'refuted'))")
            args.append(_now())
        elif status:
            conditions.append("status=?")
            args.append(status)
            if status != "refuted":
                conditions.append("(expires_at='' OR expires_at>?)")
                args.append(_now())
        for term in _text(query, "query", 1000, required=False).casefold().split():
            conditions.append("search_text LIKE ? ESCAPE '\\'")
            args.append("%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        where = " AND ".join(conditions)
        with self._lock:
            total = self._db.execute(f"SELECT COUNT(*) FROM observation_flags WHERE {where}", args).fetchone()[0]
            rows = self._db.execute(
                f"SELECT id FROM observation_flags WHERE {where} ORDER BY created_at DESC,id LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
            items = [self._row("observation_flags", project, r["id"]) for r in rows]
        return {"flags": items, "total": total, "next_offset": offset + len(items) if offset + len(items) < total else None}

    def update(self, project: str, flag_id: str, status: str, reason: str,
               evidence: list[EvidenceRef | dict] | None = None) -> dict:
        project = _text(project, "project", 300)
        if status not in FLAG_STATES:
            raise ValueError("invalid flag status")
        reason = _text(reason, "reason")
        refs = _evidence(evidence or [], required=status in {"reviewed", "refuted"})
        with self._lock, self._db:
            before = self._row("observation_flags", project, flag_id)
            if status in {"new", "reviewed"} and before["expires_at"] and before["expires_at"] <= _now():
                raise ValueError("expired observations require a new observation with fresh evidence")
            self._db.execute("UPDATE observation_flags SET status=?,updated_at=? WHERE id=?",
                             (status, _now(), flag_id))
            self._event(project, flag_id, "review", {"before": before["status"], "status": status,
                                                     "reason": reason, "evidence": refs})
        return self.get(project, flag_id, include_history=True)

    def link(self, project: str, src: str, dst: str, relation: str, reason: str,
             *, active: bool = True) -> dict:
        project = _text(project, "project", 300)
        reason = _text(reason, "reason")
        if src == dst:
            raise ValueError("cannot link a flag to itself")
        with self._lock, self._db:
            self._row("observation_flags", project, src)
            if dst.startswith("hyp_"):
                self._row("analysis_hypotheses", project, dst)
                if relation not in {"supports", "contradicts"}:
                    raise ValueError("hypothesis relation must be supports or contradicts")
                table, left, right, values = "hypothesis_flags", "hypothesis_id", "flag_id", (dst, src)
            else:
                self._row("observation_flags", project, dst)
                if relation not in {"supports", "contradicts", "related", "derived_from"}:
                    raise ValueError("invalid flag relation")
                table, left, right, values = "flag_relations", "src", "dst", (src, dst)
            existing = self._db.execute(
                f"SELECT * FROM {table} WHERE {left}=? AND {right}=? AND relation=?",
                (*values, relation)).fetchone()
            if not active and existing is None:
                raise ValueError("cannot retire a relation that does not exist")
            if existing and existing["reason"] == reason and bool(existing["active"]) == active:
                return {"src": src, "dst": dst, "relation": relation, "reason": reason, "active": active}
            self._db.execute(
                f"INSERT INTO {table} VALUES(?,?,?,?,?,?) ON CONFLICT({left},{right},relation) "
                "DO UPDATE SET reason=excluded.reason,active=excluded.active",
                (*values, relation, reason, _now(), int(active)))
            self._event(project, dst, "linked" if active else "relation_retired",
                        {"src": src, "relation": relation, "reason": reason,
                         "before": dict(existing) if existing else None, "active": active})
        return {"src": src, "dst": dst, "relation": relation, "reason": reason, "active": active}

    @staticmethod
    def _terms(item: dict) -> set[str]:
        return {"h:" + item["target_key"],
                *("e:" + value for value in item["entities"]),
                *("t:" + value for value in item["tags"]),
                *("r:" + ref["ref"] for ref in item["evidence"]),
                *("g:" + ref["source_group"] for ref in item["evidence"])}

    def related(self, project: str, flag_id: str, *, limit: int = 5) -> list[dict]:
        project = _text(project, "project", 300)
        if not 1 <= limit <= 20:
            raise ValueError("limit must be 1..20")
        with self._lock:
            item = self._row("observation_flags", project, flag_id)
            terms = sorted(self._terms(item))
            slots = ",".join("?" for _ in terms)
            # Indexed context lookup/ranking precedes LIMIT. No scan/deserialization
            # of every project flag, and no recent-history window hiding old clues.
            candidates = self._db.execute(
                "SELECT f.id,SUM(CASE substr(t.term,1,2) WHEN 'e:' THEN 5 WHEN 't:' THEN 2 "
                "WHEN 'h:' THEN 1 ELSE 3 END) AS relevance FROM flag_context_terms t "
                "JOIN observation_flags f ON f.id=t.flag_id "
                f"WHERE t.project=? AND f.id<>? AND t.term IN ({slots}) "
                "GROUP BY f.id ORDER BY relevance DESC,f.created_at DESC,f.id LIMIT ?",
                (project, flag_id, *terms, limit),
            ).fetchall()
            matches = []
            for candidate in candidates:
                other = self._row("observation_flags", project, candidate["id"])
                shared_entities = set(item["entities"]) & set(other["entities"])
                shared_tags = set(item["tags"]) & set(other["tags"])
                shared_refs = {r["ref"] for r in item["evidence"]} & {r["ref"] for r in other["evidence"]}
                shared_groups = {r["source_group"] for r in item["evidence"]} & {r["source_group"] for r in other["evidence"]}
                same_host = item["target_key"] == other["target_key"]
                score = 5 * bool(shared_entities) + 2 * bool(shared_tags) + 3 * bool(shared_refs or shared_groups) + int(same_host)
                if not score:
                    continue
                matches.append({"flag_id": other["id"], "observation": other["observation"],
                                "target": other["target"], "auth_context": other["auth_context"],
                                "effective_status": other["effective_status"],
                                "same_host": same_host, "shared_entities": sorted(shared_entities),
                                "shared_tags": sorted(shared_tags), "shared_source": bool(shared_refs or shared_groups),
                                "different_auth_context": item["auth_context"] != other["auth_context"],
                                "rank": candidate["relevance"]})
            return [{k: v for k, v in match.items() if k != "rank"} for match in matches[:limit]]

    def propose(self, project: str, target: str, claim: str, flag_ids: list[str],
                test_plan: str, expected_observation: str, *, alternatives: list[str] | None = None,
                contradicting_flags: list[str] | None = None, run_id: str = "") -> dict:
        project = _text(project, "project", 300)
        claim = _text(claim, "claim")
        if not flag_ids or len(flag_ids) > 50 or len(contradicting_flags or []) > 50:
            raise ValueError("provide 1..50 supporting flags and at most 50 contradicting flags")
        tests = _text(test_plan, "test_plan")
        expected = _text(expected_observation, "expected_observation")
        alternatives = _strings(alternatives, "alternatives")
        hypothesis_id, now = "hyp_" + uuid.uuid4().hex, _now()
        with self._lock, self._db:
            for flag_id in set(flag_ids + (contradicting_flags or [])):
                self._row("observation_flags", project, flag_id)
            self._db.execute("INSERT INTO analysis_hypotheses VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                             (hypothesis_id, project, _text(target, "target", 2000), target_key(target), claim,
                              _json(alternatives), tests, expected, _text(run_id, "run_id", 100, required=False),
                              "proposed", now, now))
            for relation, ids in [("supports", flag_ids), ("contradicts", contradicting_flags or [])]:
                for flag_id in set(ids):
                    self._db.execute("INSERT INTO hypothesis_flags VALUES(?,?,?,?,?,?)",
                                     (hypothesis_id, flag_id, relation, "Provided with hypothesis", now, 1))
            self._event(project, hypothesis_id, "proposed", {"claim": claim})
        return self.hypothesis(project, hypothesis_id)

    def hypothesis(self, project: str, hypothesis_id: str, *, include_history: bool = False) -> dict:
        project = _text(project, "project", 300)
        with self._lock:
            item = self._row("analysis_hypotheses", project, hypothesis_id)
            linked = [dict(r) for r in self._db.execute(
                "SELECT flag_id,relation,reason,active FROM hypothesis_flags WHERE hypothesis_id=? ORDER BY flag_id,relation",
                (hypothesis_id,))]
            refs, stale_support, contradictions = [], [], []
            for row in linked:
                flag = self._row("observation_flags", project, row["flag_id"])
                row["effective_status"] = flag["effective_status"]
                row["observation"] = flag["observation"]
                row["auth_context"] = flag["auth_context"]
                if not row["active"]:
                    continue
                if row["relation"] == "supports":
                    refs.extend(flag["evidence"])
                    if flag["effective_status"] in {"stale", "refuted"}:
                        stale_support.append(row["flag_id"])
                elif flag["effective_status"] not in {"refuted", "stale"}:
                    contradictions.append(row["flag_id"])
            item["flags"] = linked
            item["support_source_groups"] = sorted({ref["source_group"] for ref in refs})
            item["support_evidence_refs"] = sorted({ref["ref"] for ref in refs})
            item["source_note"] = "Source groups are declared provenance, not proof of independent evidence."
            item["invalid_support"] = stale_support
            item["contradicting_flags"] = contradictions
            item["missing_support"] = not any(row["active"] and row["relation"] == "supports" for row in linked)
            item["needs_review"] = bool(stale_support or contradictions or item["missing_support"])
            item["effective_status"] = "stale" if item["needs_review"] and item["status"] == "supported" else item["status"]
            item["finding_promoted"] = False
            if include_history:
                item["history"] = self.history(project, hypothesis_id)
            return item

    def hypotheses(self, project: str, *, target: str = "", run_id: str = "",
                   limit: int = 20, offset: int = 0) -> dict:
        conditions, args = ["project=?"], [_text(project, "project", 300)]
        if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise ValueError("limit must be 1..100; offset must be 0..100000")
        if target:
            conditions.append("target_key=?")
            args.append(target_key(target))
        if run_id:
            conditions.append("run_id=?")
            args.append(run_id)
        where = " AND ".join(conditions)
        with self._lock:
            total = self._db.execute(f"SELECT COUNT(*) FROM analysis_hypotheses WHERE {where}", args).fetchone()[0]
            rows = self._db.execute(
                f"SELECT id FROM analysis_hypotheses WHERE {where} ORDER BY created_at DESC,id LIMIT ? OFFSET ?",
                [*args, limit, offset]).fetchall()
            items = [self.hypothesis(project, r["id"]) for r in rows]
        return {"hypotheses": items, "total": total,
                "next_offset": offset + len(items) if offset + len(items) < total else None}

    def review_hypothesis(self, project: str, hypothesis_id: str, status: str, reason: str,
                          evidence: list[EvidenceRef | dict] | None = None,
                          test_outcome: str = "not_run") -> dict:
        project = _text(project, "project", 300)
        if status not in HYPOTHESIS_STATES:
            raise ValueError("invalid hypothesis status")
        if test_outcome not in {"not_run", "completed", "failed", "blocked"}:
            raise ValueError("invalid test_outcome")
        if status in {"supported", "refuted"} and test_outcome != "completed":
            raise ValueError("support/refutation requires a completed check; a failed check is inconclusive")
        reason = _text(reason, "reason")
        refs = _evidence(evidence or [], required=status in {"supported", "refuted", "inconclusive"})
        with self._lock, self._db:
            before = self.hypothesis(project, hypothesis_id)
            if status == "supported" and before["needs_review"]:
                raise ValueError("resolve contradicting flags and retire stale/refuted support links before supporting the hypothesis")
            if status == "supported" and not any(f["active"] and f["relation"] == "supports" for f in before["flags"]):
                raise ValueError("hypothesis requires active supporting flags")
            self._db.execute("UPDATE analysis_hypotheses SET status=?,updated_at=? WHERE id=?",
                             (status, _now(), hypothesis_id))
            self._event(project, hypothesis_id, "review", {"before": before["status"], "status": status,
                        "reason": reason, "evidence": refs, "test_outcome": test_outcome})
        return self.hypothesis(project, hypothesis_id, include_history=True)

    def brief(self, project: str, *, target: str = "", run_id: str = "", limit: int = 10) -> dict:
        flags = self.query(project, target=target, run_id=run_id, limit=limit)
        hypotheses = self.hypotheses(project, target=target, run_id=run_id, limit=limit)
        return {"project": project, "target": target or None, "flags": flags,
                "hypotheses": hypotheses,
                "hint": "Flags are observations. Correlations suggest checks; they never confirm a vulnerability."}
