"""Regression coverage for scoped retrieval, immutable trust versions and migration."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from moonmcp.memory import _SCHEMA, MemoryStore, normalize_target


@pytest.mark.parametrize(("target", "key"), [
    ("HTTPS://Example.COM.:8443/Case?Token=X", "example.com"),
    ("https://user:pass@notexample.com/a?example.com", "notexample.com"),
    ("https://BÜCHER.example:443/Case", "xn--bcher-kva.example"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ("https://[2001:0db8::1]:443/Case", "2001:db8::1"),
    ("2001:0db8::1", "2001:db8::1"),
    ("example.com:443", "example.com"),
])
def test_target_normalization(target, key):
    assert normalize_target(target) == key


def test_brief_and_search_never_match_substrings_or_subdomains():
    m = MemoryStore()
    original = "HTTPS://Example.COM.:8443/Case?Token=X"
    wanted = m.add(kind="finding", title="expected", target=original)
    for target in ("https://notexample.com/", "https://example.com.evil/",
                   "https://sub.example.com/", "https://evil.test/example.com",
                   "https://example.com@evil.test/"):
        m.add(kind="finding", title="other", target=target)
    assert [x["id"] for x in m.search("", target="example.com")] == [wanted]
    result = m.brief("https://EXAMPLE.com:80/unrelated")
    assert result["counts"]["findings"] == 1
    assert result["findings"][0]["target"] == original


def test_idna_and_ipv6_host_retrieval():
    m = MemoryStore()
    unicode_id = m.add(kind="note", title="unicode", target="https://BÜCHER.example/Case")
    ipv6_id = m.add(kind="note", title="ipv6", target="https://[2001:0db8::1]:443/Case")
    assert [x["id"] for x in m.search("", target="xn--bcher-kva.example")] == [unicode_id]
    assert [x["id"] for x in m.search("", target="[2001:db8::1]")] == [ipv6_id]


def test_upsert_preserves_case_sensitive_url_context():
    m = MemoryStore()
    first = m.add(kind="note", title="signal", target="https://EXAMPLE.com/Case?Token=X")
    equivalent = m.add(kind="note", title="signal", target="HTTPS://example.com/Case?Token=X")
    other_path = m.add(kind="note", title="signal", target="https://example.com/case?Token=X")
    other_query = m.add(kind="note", title="signal", target="https://example.com/Case?Token=x")
    assert first == equivalent
    assert len({first, other_path, other_query}) == 3
    assert len(m.search("", target="example.com")) == 3


def test_bare_host_identity_normalizes_idna_without_lowercasing_query():
    m = MemoryStore()
    first = m.add(kind="note", title="signal", target="BÜCHER.example?Token=X")
    equivalent = m.add(kind="note", title="signal", target="xn--bcher-kva.example?Token=X")
    distinct = m.add(kind="note", title="signal", target="BÜCHER.example?Token=x")
    assert first == equivalent and distinct != first


@pytest.mark.parametrize("query", ["", "signal"])
@pytest.mark.parametrize("fallback", [False, True])
def test_filters_precede_limit_for_recent_fts_and_fallback(query, fallback):
    m = MemoryStore()
    wanted = m.add(kind="finding", title="signal wanted", target="https://example.com/Case",
                   trust="curated")
    for index in range(240):
        m.add(kind="note", title=f"signal noise {index}", target="other.test")
    if fallback:
        m._fts = False
    assert [x["id"] for x in m.search(query, target="example.com", limit=1)] == [wanted]
    assert [x["id"] for x in m.search(query, kind="finding", limit=1)] == [wanted]
    assert [x["id"] for x in m.search(query, trust="curated", limit=1)] == [wanted]
    assert [x["id"] for x in m.recent(limit=1, kind="finding")] == [wanted]


def test_brief_uses_target_and_kind_before_limits_with_exact_counts():
    m = MemoryStore()
    m.add(kind="finding", title="old finding", target="https://example.com/Case")
    for index in range(205):
        m.add(kind="observation", title=f"observation {index}", target="example.com")
        m.add(kind="finding", title=f"other finding {index}", target="other.test")
    result = m.brief("example.com")
    assert [x["title"] for x in result["findings"]] == ["old finding"]
    assert result["counts"] == {"entities": 0, "findings": 1, "leads": 205}
    assert len(result["leads"]) == len(result["lead_items"]) == 50


def test_entity_and_relation_filters_precede_limits():
    m = MemoryStore()
    wanted = m.add_entity(kind="host", name="example.com", target="https://example.com/Case")
    m.add_relation("host:example.com", "uses", "technology:expected", target="example.com")
    for index in range(100):
        m.add_entity(kind="technology", name=f"noise{index}", target="other.test")
        m.add_relation("host:other.test", "uses", f"technology:noise{index}", target="other.test")
    assert [x["id"] for x in m.entities(target="example.com", limit=1)] == [wanted]
    assert [x["id"] for x in m.entities(kind="host", limit=1)] == [wanted]
    graph = m.graph("example.com", limit=1)
    assert [x["id"] for x in graph["entities"]] == [wanted]
    assert graph["relations"] == [{"src": "host:example.com", "rel": "uses",
                                    "dst": "technology:expected"}]


def test_untrusted_revision_cannot_replace_curated_content_or_index(tmp_path):
    path = str(tmp_path / "memory.db")
    m = MemoryStore(path)
    item_id = m.add(kind="finding", title="shared title", body="vetted evidence",
                    source="review", provenance="manual", trust="curated", target="example.com",
                    severity="low", tags="reviewed", session="trusted")
    original = m.get(item_id)
    assert original is not None
    assert m.add(kind="finding", title="shared title", body="unreviewed replacement",
                 source="target response", provenance="extracted", trust="untrusted",
                 target="example.com", severity="critical", tags="new", session="scraped") == item_id
    current = m.get(item_id)
    assert current is not None
    for key in ("body", "source", "provenance", "trust", "severity", "tags", "session",
                "revision", "content_hash"):
        assert current[key] == original[key]
    assert current["revision_count"] == 2 and current["pending_revisions"] == 1
    assert not m.search("replacement")
    assert m.search("vetted", trust="curated")[0]["id"] == item_id
    history = m.revisions(item_id)
    assert history[0]["content"]["body"] == "unreviewed replacement"
    assert history[0]["trust"] == "untrusted" and not history[0]["accepted"]
    assert not history[0]["is_current"] and history[1]["is_current"]
    assert history[0]["content_hash"] != history[1]["content_hash"]
    m.close()
    m = MemoryStore(path)
    assert m.revisions(item_id) == history
    m.add(kind="finding", title="shared title", body="second vetted version",
          target="example.com", trust="curated")
    latest = m.revisions(item_id)
    assert latest[0]["accepted"] and latest[0]["is_current"]
    assert latest[0]["revision"] == 3
    assert {k: v for k, v in latest[-1].items() if k != "is_current"} == {
        k: v for k, v in history[-1].items() if k != "is_current"}
    assert m.get(item_id)["body"] == "second vetted version"


def test_entity_history_retains_vetted_attributes(tmp_path):
    m = MemoryStore(str(tmp_path / "memory.db"))
    entity_id = m.add_entity(kind="technology", name="service", target="example.com",
                             attrs='{"version":"reviewed"}', trust="curated")
    m.add_entity(kind="technology", name="service", target="example.com",
                  attrs='{"version":"unverified"}', trust="untrusted")
    entity = m.entities(target="example.com")[0]
    assert entity["attrs"] == '{"version":"reviewed"}'
    assert entity["revision_count"] == 2 and entity["pending_revisions"] == 1
    history = m.entity_revisions(entity_id)
    assert history[0]["content"]["attrs"] == '{"version":"unverified"}'
    assert history[0]["trust"] == "untrusted" and not history[0]["accepted"]
    assert history[1]["content_hash"] == entity["content_hash"]


def test_identical_repeated_upserts_do_not_inflate_revision_history():
    m = MemoryStore()
    for _ in range(3):
        item_id = m.add(kind="note", title="same", body="same", trust="curated")
        entity_id = m.add_entity(kind="host", name="example.com", attrs="same", trust="curated")
    assert len(m.revisions(item_id)) == len(m.entity_revisions(entity_id)) == 1
    for _ in range(3):
        m.add(kind="note", title="same", body="proposal")
        m.add_entity(kind="host", name="example.com", attrs="proposal")
    assert len(m.revisions(item_id)) == len(m.entity_revisions(entity_id)) == 2
    assert m.get(item_id)["body"] == "same"
    assert m.entities()[0]["attrs"] == "same"


def test_legacy_database_migration_keeps_ids_content_and_graph(tmp_path):
    path = str(tmp_path / "legacy.db")
    db = sqlite3.connect(path)
    db.executescript(_SCHEMA)
    db.execute("INSERT INTO memory(id,kind,title,body,target,trust) VALUES(42,?,?,?,?,?)",
               ("finding", "legacy finding", "legacy evidence", "https://BÜCHER.example/Case", "curated"))
    db.execute("INSERT INTO entities(id,kind,name,target,attrs,trust) VALUES(9,?,?,?,?,?)",
               ("host", "bücher.example", "BÜCHER.example", "vetted attrs", "curated"))
    db.execute("INSERT INTO relations(src,rel,dst,target) VALUES(?,?,?,?)",
               ("finding:42", "affects", "host:bücher.example", "BÜCHER.example"))
    db.commit()
    db.close()
    m = MemoryStore(path)
    assert m.get(42)["body"] == "legacy evidence"
    assert m.revisions(42)[0]["content"]["body"] == "legacy evidence"
    assert m.search("legacy", target="xn--bcher-kva.example")[0]["id"] == 42
    graph = m.graph("xn--bcher-kva.example")
    assert graph["entities"][0]["id"] == 9
    assert len(graph["relations"]) == 1
    assert m.entity_revisions(9)[0]["content"]["attrs"] == "vetted attrs"
    m.close()
    m = MemoryStore(path)
    assert len(m.revisions(42)) == len(m.entity_revisions(9)) == 1


def test_reopen_does_not_rebuild_fts_and_index_stays_current(tmp_path, monkeypatch):
    path = str(tmp_path / "memory.db")
    m = MemoryStore(path)
    if not m.stats()["fts"]:
        pytest.skip("SQLite has no FTS5")
    item_id = m.add(kind="note", title="oldtitle", body="oldbody")
    m.close()
    statements = []
    connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    m = MemoryStore(path)
    assert not any("rebuild" in statement.lower() for statement in statements)
    m.add(kind="note", title="oldtitle", body="newbody")
    assert not m.search("oldbody")
    assert m.search("newbody")[0]["id"] == item_id
    assert m.clear() == 1
    assert not m.search("newbody") and not m.revisions(item_id)


def test_clear_url_does_not_expand_to_other_paths():
    m = MemoryStore()
    first = m.add(kind="note", title="a", target="https://example.com/A")
    second = m.add(kind="note", title="b", target="https://example.com/B")
    assert m.clear("https://EXAMPLE.com/A") == 1
    assert m.get(first) is None and not m.revisions(first)
    assert m.get(second) is not None


def test_concurrent_store_instances_keep_atomic_revisions(tmp_path):
    path = str(tmp_path / "memory.db")
    stores = [MemoryStore(path), MemoryStore(path)]

    def add(index):
        return stores[index % 2].add(kind="note", title="same signature", body=f"version {index}")

    with ThreadPoolExecutor(max_workers=2) as executor:
        ids = list(executor.map(add, range(12)))
    assert len(set(ids)) == 1
    revisions = stores[0].revisions(ids[0])
    assert [item["revision"] for item in revisions] == list(range(12, 0, -1))
    assert sum(item["is_current"] for item in revisions) == 1


def test_unicode_memory_search():
    m = MemoryStore()
    item_id = m.add(kind="note", title="проверка авторизации", body="身份验证 인증")
    assert m.search("авторизации")[0]["id"] == item_id
    assert m.search("身份验证")[0]["id"] == item_id
    assert m.search("인증")[0]["id"] == item_id
