"""hermes-pipeline tools, absorbed into MoonMCP.

The old Node server (hermes_pipeline/mcp_server/index.js) exposed 13 tools
over the same knowledge bases this repo ships. MoonMCP now serves them all
from one Python process, so the second MCP server can be retired.

Everything here is passive (local files/SQLite, zero traffic) — the whole
module belongs in the PASSIVE allowlist of tests/test_active_tool_guard.py.

Paths resolve against the *deployed* pipeline copy (``~/hermes_pipeline``)
with the dev copy (``~/Desktop/hermes_pipeline``) as fallback, so the tools
keep working regardless of which tree is current.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

_PIPELINE_DIRS = [
    Path.home() / "hermes_pipeline",
    Path.home() / "Desktop" / "hermes_pipeline",
]
"""Deployed copy first (the one targets.yaml/KB on disk belongs to), dev copy
second so the tools survive either checkout being current."""

_MAX_FILE_BYTES = 5_000_000
_MAX_MATCHES = 20

KB_SOURCES: dict[str, str] = {
    "waf_bypass": "waf_bypass",
    "payloads": "payloads_all_the_things",
    "zero_trust": "zero_trust",
    "kernel_exploitation": "kernel_exploitation",
    "business_logic": "business_logic",
    "writeups": "writeups",
    "chained_writeups": "chained_writeups",
    "creative_writeups": "creative_writeups",
    "enumeration_methodology": "enumeration_methodology",
    "src_hunter_cn": "src_hunter_cn",
    "ssrf_cloud_metadata": "ssrf_cloud_metadata",
    "graphql_security": "graphql_security",
    "owasp_cheatsheets": "owasp_cheatsheets",
    "secret_patterns": "secret_patterns",
    "hacktricks": "hacktricks",
}

REPORT_TYPE_MAP: dict[str, str] = {
    "idor": "TOPIDOR.md",
    "auth": "TOPAUTH.md",
    "authorization": "TOPAUTHORIZATION.md",
    "authz": "TOPAUTHORIZATION.md",
    "sqli": "TOPSQLI.md",
    "sql": "TOPSQLI.md",
    "xss": "TOPXSS.md",
    "ssrf": "TOPSSRF.md",
    "rce": "TOPRCE.md",
    "csrf": "TOPCSRF.md",
    "xxe": "TOPXXE.md",
    "ssti": "TOPSSTI.md",
    "graphql": "TOPGRAPHQL.md",
    "oauth": "TOPOAUTH.md",
    "openid": "TOPOPENID.md",
    "open-redirect": "TOPOPENREDIRECT.md",
    "redirect": "TOPOPENREDIRECT.md",
    "account-takeover": "TOPACCOUNTTAKEOVER.md",
    "ato": "TOPACCOUNTTAKEOVER.md",
    "race-condition": "TOPRACECONDITION.md",
    "race": "TOPRACECONDITION.md",
    "info-disclosure": "TOPINFODISCLOSURE.md",
    "disclosure": "TOPINFODISCLOSURE.md",
    "upload": "TOPUPLOAD.md",
    "mfa": "TOPMFA.md",
    "mobile": "TOPMOBILE.md",
    "business-logic": "TOPBUSINESSLOGIC.md",
    "clickjacking": "TOPCLICKJACKING.md",
    "dos": "TOPDOS.md",
    "file-reading": "TOPFILEREADING.md",
    "request-smuggling": "TOPREQUESTSMUGGLING.md",
    "smuggling": "TOPREQUESTSMUGGLING.md",
    "subdomain-takeover": "TOPSUBDOMAINTAKEOVER.md",
    "webcache": "TOPWEBCACHE.md",
    "api": "TOPAPI.md",
}

AIRECON_DBS: dict[str, dict[str, str]] = {
    "bug_bounty_pentest": {
        "file": "bug-bounty-pentest.db",
        "label": "Bug Bounty & Pentest Methodology (146 записей: exploitation steps, payloads, WAF bypass, report templates)",
    },
    "web_vuln_patterns": {
        "file": "airecon-web-vuln-patterns.db",
        "label": "Web Vulnerability Detection Patterns (3000 записей: HTTP-индикаторы XSS/SQLi/SSTI/SSRF/LFI/RCE + validation steps)",
    },
    "nuclei_templates": {
        "file": "nuclei-templates.db",
        "label": "Nuclei Templates Instruct (23180 записей: canonical CVE records + готовые DAST шаблоны)",
    },
}

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------- helpers

def _first(*rel: str) -> Path | None:
    """First existing path across the pipeline dirs, else None."""
    for base in _PIPELINE_DIRS:
        p = base.joinpath(*rel)
        if p.exists():
            return p
    return None


def _queue_file() -> Path:
    for base in _PIPELINE_DIRS:
        q = base / "hermes_queue.jsonl"
        if q.exists():
            return q
    return _PIPELINE_DIRS[0] / "hermes_queue.jsonl"


def _read_queue() -> list[dict[str, Any]]:
    q = _queue_file()
    if not q.exists():
        return []
    items = []
    for line in q.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def _targets_fallback_parser(text: str) -> dict[str, Any]:
    """Minimal stdlib parser for the simple targets.yaml shape (flat dict of
    dicts with scalar values, one nested `headers` mapping). Only used when
    PyYAML is unavailable — keeps the zero-dependency contract."""
    targets: dict[str, Any] = {}
    current: dict[str, Any] | None = None
    section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip() if not raw_line.lstrip().startswith("#") else ""
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0:
            if not stripped.endswith(":"):
                continue
            current = {}
            targets[stripped[:-1]] = current
            section = None
        elif current is not None and stripped.endswith(":") and indent <= 2:
            section = stripped[:-1]
            current[section] = {}
        elif current is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            value = value.strip().strip("'\"")
            if section and indent >= 4:
                current.setdefault(section, {})[key.strip()] = value
            else:
                current[key.strip()] = value
    return targets


def _load_targets() -> dict[str, Any]:
    t = _first("targets.yaml")
    if t is None:
        return {}
    text = t.read_text(encoding="utf-8")
    try:
        import yaml  # optional dependency, like recon/openapi.py
    except ImportError:
        return _targets_fallback_parser(text)
    try:
        data = yaml.safe_load(text) or {}
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 — malformed YAML is data, not a crash
        return {}


def _resolve_env_vars(value: str) -> str:
    return re.sub(
        r"\{\{(\w+)\}\}",
        lambda m: os.environ.get(m.group(1), f"<MISSING_{m.group(1)}>"),
        value,
    )


def _grep_kb(source_dir: Path, keyword: str,
             max_matches: int = _MAX_MATCHES,
             max_file_bytes: int = _MAX_FILE_BYTES) -> list[dict[str, Any]]:
    """Recursive case-insensitive grep over .md/.txt/.toml/.json, capped."""
    kw = keyword.lower()
    results: list[dict[str, Any]] = []
    for path in source_dir.rglob("*"):
        if len(results) >= max_matches:
            break
        if path.name.startswith(".git"):
            continue
        if not path.is_file() or not re.search(r"\.(md|txt|toml|json)$", path.name, re.I):
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(content.splitlines()):
            if kw in line.lower():
                results.append({
                    "file": str(path.relative_to(source_dir)),
                    "line": i + 1,
                    "text": line.strip()[:300],
                })
                if len(results) >= max_matches:
                    break
    return results


def _fmt_report_line(entry: dict[str, Any]) -> str:
    title = entry.get("title", "").strip()
    url = entry.get("url", "")
    author = (entry.get("author") or {}).get("name", "") if isinstance(entry.get("author"), dict) else str(entry.get("author") or "")
    upvotes = entry.get("upvotes", 0)
    bounty = entry.get("bounty")
    bounty_s = f", ${bounty}" if bounty else ""
    return f"{title} ({url}) to {author} — {upvotes} upvotes{bounty_s}"


def _severity_sort_sql() -> str:
    return ("CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC")


# ------------------------------------------------------------ tool logic

def queue_task(text: str, target: str | None = None) -> str:
    q = _queue_file()
    q.parent.mkdir(parents=True, exist_ok=True)
    item: dict[str, Any] = {"ts": time.time(), "text": text}
    if target:
        item["target"] = target
    with q.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")
    return f"Задача поставлена в очередь (id={item['ts']}): {text}"


def list_queue() -> str:
    items = _read_queue()
    if not items:
        return "Очередь пуста."
    return "\n".join(f"[{it.get('ts', '?')}] {it.get('text', '')}" for it in items)


def get_target(name: str) -> str:
    targets = _load_targets()
    t = targets.get(name)
    if not t:
        return (f"Таргет \"{name}\" не найден. Доступные: "
                f"{', '.join(targets) or 'нет настроенных таргетов'}")
    headers = {k: _resolve_env_vars(v) for k, v in (t.get("headers") or {}).items()}
    return json.dumps({
        "base_url": t.get("base_url"),
        "headers": headers,
        "scope": t.get("scope") or None,
    }, indent=2, ensure_ascii=False)


def list_targets() -> str:
    targets = _load_targets()
    return ", ".join(targets) if targets else "targets.yaml пуст или не найден."


def search_bugbounty_reports(vuln_type: str, limit: int = 10) -> str:
    key = vuln_type.lower().strip()
    fname = REPORT_TYPE_MAP.get(key)
    if not fname:
        known = ", ".join(REPORT_TYPE_MAP)  # insertion order, as before
        return f"Неизвестный тип уязвимости \"{vuln_type}\". Доступные: {known}"
    path = _first("knowledge_base", "hackerone_reports", "tops_by_bug_type", fname)
    if path is None:
        return f"Файл {fname} не найден в базе репортов."
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return f"Ошибка чтения {fname}."
    # The TOP*.md files are markdown numbered lists — keep report lines only.
    numbered = [line.strip() for line in raw.split("\n")
                if re.match(r"^\d+\.", line.strip())]
    selected = numbered[:limit]
    if selected:
        return "\n".join(selected)
    return "\n".join(raw.split("\n")[:limit + 2])


def list_report_categories() -> str:
    return ", ".join(sorted(REPORT_TYPE_MAP))


def search_knowledge_base(source: str, keyword: str, limit: int = 20) -> str:
    dir_name = KB_SOURCES.get(source)
    if not dir_name:
        return (f"Неизвестный источник \"{source}\". Доступные: "
                f"{', '.join(KB_SOURCES)}")
    base = _first("knowledge_base")
    if base is None:
        return "База знаний (knowledge_base/) не найдена."
    source_dir = base / dir_name
    if not source_dir.exists():
        return f"Директория {dir_name} не найдена в базе знаний."
    matches = _grep_kb(source_dir, keyword, max_matches=limit)
    if not matches:
        return f"Совпадений для \"{keyword}\" в {source} не найдено."
    # Node parity: paths relative to the knowledge_base root (dir_name/…).
    return "\n".join(
        f"{dir_name}/{m['file']}:{m['line']}: {m['text']}" for m in matches
    )


def search_datasets(dataset: str, query: str, limit: int = 5,
                    full_answer: bool = False) -> str:
    info = AIRECON_DBS.get(dataset)
    if not info:
        return (f"Неизвестный датасет \"{dataset}\". Доступные: "
                f"{', '.join(AIRECON_DBS)}")
    db_path = _first("knowledge_base", "airecon_datasets", info["file"])
    if db_path is None:
        return f"База {info['file']} не найдена в knowledge_base/airecon_datasets/"
    limit = max(1, min(limit, 10))
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows: list[tuple] = []
        try:
            rows = con.execute(
                "SELECT r.id, r.query, r.answer, r.category, r.source "
                "FROM records_fts f JOIN records r ON r.rowid = f.rowid "
                "WHERE records_fts MATCH ? LIMIT ?",
                (query, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            like = f"%{query.lower()}%"
            rows = con.execute(
                "SELECT id, query, answer, category, source FROM records "
                "WHERE LOWER(query) LIKE ? OR LOWER(answer) LIKE ? LIMIT ?",
                (like, like, limit),
            ).fetchall()
        if not rows:
            return f"Совпадений для \"{query}\" в {dataset} не найдено."
        parts = []
        for r in rows:
            answer = r[2] if full_answer else r[2][:500] + ("…" if len(r[2]) > 500 else "")
            parts.append(f"[#{r[0]} | {r[3] or ''}]\nQ: {r[1]}\nA: {answer}\n---")
        return f"Датасет: {info['label']}\n\n" + "\n".join(parts)
    finally:
        con.close()


def match_signature_to_cve(technology: str, min_severity: str | None = None,
                           limit: int = 15) -> str:
    db_path = _first("knowledge_base", "nuclei_index.sqlite3")
    if db_path is None:
        return "Индекс nuclei-templates не найден. Запусти build_nuclei_index.py."
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        tech = f"%{technology.lower()}%"
        sql = ("SELECT id, name, severity, tags, description, shodan_query, reference "
               "FROM templates WHERE (LOWER(tags) LIKE ? OR LOWER(name) LIKE ?)")
        params: list[Any] = [tech, tech]
        if min_severity:
            min_level = _SEVERITY_ORDER.get(min_severity.lower())
            if min_level is not None:
                allowed = ",".join(f"'{k}'" for k, v in _SEVERITY_ORDER.items() if v >= min_level)
                sql += f" AND severity IN ({allowed})"
        sql += f" ORDER BY {_severity_sort_sql()} LIMIT ?"
        params.append(limit)
        rows = con.execute(sql, params).fetchall()
    finally:
        con.close()
    if not rows:
        return f"Совпадений для \"{technology}\" не найдено в индексе."
    lines = []
    for r in rows:
        ref = f"\n  ref: {r[6]}" if r[6] else ""
        lines.append(f"[{(r[2] or '').upper()}] {r[0]} — {r[1]}{ref}")
    return "\n".join(lines)


def get_nuclei_template(template_id: str) -> str:
    db_path = _first("knowledge_base", "nuclei_index.sqlite3")
    if db_path is None:
        return "Индекс nuclei-templates не найден."
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = con.execute("SELECT filepath FROM templates WHERE id = ?",
                          (template_id,)).fetchone()
    finally:
        con.close()
    if not row:
        return f"Шаблон {template_id} не найден в индексе."
    filepath = row[0]
    if not os.path.exists(filepath):
        return f"Файл шаблона отсутствует на диске: {filepath}"
    try:
        return Path(filepath).read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        return f"Ошибка чтения шаблона: {e}"


def search_web_security_resources(category: str, keyword: str | None = None,
                                  difficulty: str | None = None,
                                  language: str | None = None,
                                  type_: str | None = None,
                                  limit: int = 15) -> str:
    idx_path = _first("knowledge_base", "web_security_index", "index.json")
    if idx_path is None:
        return "Индекс web_security_index/index.json не найден."
    try:
        idx = json.loads(idx_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return "Ошибка чтения web_security_index/index.json."
    results = [e for e in idx.get("entries", [])
               if e.get("category") == category.lower()]
    if keyword:
        kw = keyword.lower()
        results = [e for e in results if kw in (e.get("title") or "").lower()]
    if difficulty:
        results = [e for e in results if e.get("difficulty") == difficulty.lower()]
    if language:
        results = [e for e in results
                   if language.lower() in (e.get("languages") or [])]
    if type_:
        results = [e for e in results if e.get("type") == type_.lower()]
    results = results[:limit]
    if not results:
        return f"Ничего не найдено для категории \"{category}\" с указанными фильтрами."
    parts = []
    for e in results:
        author = e.get("author")
        author_s = f" — {author['name']}" if isinstance(author, dict) and author.get("name") else ""
        diff = f" [{e['difficulty']}]" if e.get("difficulty") else ""
        langs = f" ({','.join(e['languages'])})" if e.get("languages") else ""
        archive = f"\n  archive: {e['archive_url']}" if e.get("archive_url") else ""
        parts.append(f"{e.get('title','')}{author_s}{diff}{langs}\n  {e.get('url','')}{archive}")
    return "\n\n".join(parts)


def list_web_security_categories() -> str:
    idx_path = _first("knowledge_base", "web_security_index", "index.json")
    if idx_path is None:
        return "Индекс web_security_index/index.json не найден."
    try:
        idx = json.loads(idx_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return "Ошибка чтения web_security_index/index.json."
    return "\n".join(f"{c['key']} — {c['title']}"
                     for c in idx.get("categories", []))


def check_subdomain_takeover(service: str) -> str:
    fp_path = _first("knowledge_base", "subdomain_takeover", "fingerprints.json")
    if fp_path is None:
        return "База fingerprints.json не найдена."
    try:
        data = json.loads(fp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return "Ошибка чтения fingerprints.json."
    q = service.lower()
    matches = [d for d in data
               if q in (d.get("service") or "").lower()
               or any(q in c.lower() for c in (d.get("cname") or []))]
    if not matches:
        return f"Сервис \"{service}\" не найден в базе can-i-take-over-xyz."
    parts = []
    for m in matches:
        status = "VULNERABLE" if m.get("vulnerable") else (m.get("status") or "unknown")
        cnames = ", ".join(m.get("cname") or []) or "N/A"
        docs = f"\n  docs: {m['documentation']}" if m.get("documentation") else ""
        parts.append(
            f"{m.get('service')} [{status}]\n"
            f"  fingerprint: {m.get('fingerprint') or 'N/A'}\n"
            f"  cname: {cnames}{docs}"
        )
    return "\n\n".join(parts)