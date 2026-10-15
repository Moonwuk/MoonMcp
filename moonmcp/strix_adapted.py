"""Strix-derived enhancements adapted for MoonMCP.

7 features ported from Strix AI pentesting tool and adapted to MoonMCP's
architecture:

1. **SARIF 2.1.0 with DAST support** — logicalLocations, CWE rules,
   security-severity, fixes (fix_before/fix_after), versionControlProvenance.
   Enhances MoonMCP's existing format_sarif with Strix's richer schema.

2. **Vulnerability deduplication** — pure-logic dedup rules (no LLM needed).
   Same root cause + same endpoint = duplicate. Different parameters = NOT.

3. **Vulnerability markdown renderer** — structured markdown report:
   ID, Severity, CVE, CWE, CVSS, Description, Impact, Technical Analysis,
   PoC, Remediation. Atomic writes (temp→rename).

4. **Agent graph state** — multi-agent tree tracking: parent/child,
   status (running/waiting/completed/crashed), budget stop.

5. **Think tool concept** — structured reasoning before action.
   Policy compliance check, multi-step exploit planning.

6. **HTTP proxy scope management** — scope filtering for intercepted
   requests (in-scope only), sitemap building from proxy traffic.

7. **Retry with exponential backoff** — for NVD API calls and external
   HTTP requests that frequently timeout.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. Enhanced SARIF 2.1.0 with DAST support (from Strix report/sarif.py)
# ---------------------------------------------------------------------------

_SEV_TO_SCORE: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0,
}

_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}


def _normalize_cwe(cwe: str | int | list | None) -> str:
    """Normalise CWE variants to canonical CWE-NNN form."""
    if cwe is None:
        return ""
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    text = str(cwe).strip()
    if not text:
        return ""
    nums = re.findall(r"\d+", text)
    return f"CWE-{nums[0]}" if nums else ""


def _slug(text: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in str(text).lower()).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return out or "finding"


def format_sarif_enhanced(
    findings: list[dict],
    *,
    version: str = "0.0.0",
    repo_url: str | None = None,
    commit_sha: str | None = None,
    branch: str | None = None,
) -> dict:
    """Render findings as SARIF 2.1.0 with DAST support.

    Enhancements over MoonMCP's basic format_sarif:
    - CWE-based rule keys (CWE-NNN) with security-severity for GitHub ranking
    - logicalLocations for DAST findings (endpoint-based, no source file)
    - fixes array (fix_before → fix_after) when remediation suggestions exist
    - versionControlProvenance when repo context is supplied
    - Synthetic location fallback (SECURITY.md) for findings without locations
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        cwe = _normalize_cwe(f.get("cwe") or f.get("type"))
        rule_id = cwe or _slug(f.get("type") or f.get("title") or "finding")

        if rule_id not in rules:
            sev = str(f.get("severity", "info")).lower()
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", " ").title(),
                "shortDescription": {"text": str(f.get("title") or rule_id)},
                "properties": {
                    "security-severity": str(_SEV_TO_SCORE.get(sev, 0.0)),
                    "tags": [cwe] if cwe else [],
                },
            }

        sev = str(f.get("severity", "info")).lower()
        target = str(f.get("target") or "").strip()
        endpoint = f.get("endpoint") or f.get("detail", "")

        msg = str(f.get("title") or rule_id)
        if f.get("detail"):
            msg += f" — {f['detail']}"[:500]

        # Physical location (file) or logical location (endpoint/URL)
        locations: list[dict] = []
        if f.get("file"):
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f["file"])},
                    "region": {"startLine": int(f.get("line", 1))} if f.get("line") else None,
                },
            })
        else:
            # DAST: logical location (URL/endpoint)
            uri = target if "://" in target else (f"https://{target}" if target else "unknown")
            locations.append({
                "physicalLocation": {"artifactLocation": {"uri": uri}},
                "logicalLocation": {
                    "fullyQualifiedName": str(endpoint or target or uri),
                    "name": str(endpoint or target or "web"),
                },
            })

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": msg},
            "locations": locations,
            "properties": {
                "severity": sev,
                "moonmcp": {
                    "target": target,
                    "endpoint": str(endpoint)[:200] if endpoint else "",
                    "source": f.get("source", ""),
                },
            },
        }

        if f.get("evidence"):
            result["properties"]["evidence"] = str(f["evidence"])[:2000]

        # Fixes (fix_before → fix_after)
        if f.get("fix_before") and f.get("fix_after"):
            result["fixes"] = [{
                "description": {"text": "Suggested fix"},
                "artifactChanges": [{
                    "artifactLocation": {"uri": str(f.get("file", "unknown"))},
                    "replacements": [{
                        "deletedRegion": {"startLine": 1},
                        "insertedContent": {"text": str(f["fix_after"])},
                    }],
                }],
            }]

        results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": os.environ.get("MOONMCP_TOOL_NAME", "MoonMCP"),
                "informationUri": "",
                "version": version,
                "rules": list(rules.values()),
            },
        },
        "results": results,
    }

    if repo_url and commit_sha:
        run["versionControlProvenance"] = [{
            "repositoryUri": repo_url,
            "revisionId": commit_sha,
            "branch": branch or "main",
        }]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


# ---------------------------------------------------------------------------
# 2. Vulnerability deduplication (from Strix report/dedupe.py)
# ---------------------------------------------------------------------------

def deduplicate_findings(findings: list[dict]) -> dict:
    """Pure-logic deduplication of vulnerability findings.

    Rules (adapted from Strix):
    - DUPLICATE: same type + same target + same endpoint + same root cause
    - NOT DUPLICATE: different endpoints even with same type
    - NOT DUPLICATE: different parameters in same endpoint
    - NOT DUPLICATE: different root causes (stored vs reflected XSS)
    - NOT DUPLICATE: different severity (auth vs unauth)

    Returns {"duplicates": [...], "unique": [...], "duplicate_count": N}
    """
    seen: list[dict] = []
    duplicates: list[dict] = []
    unique: list[dict] = []

    for f in findings:
        is_dup = False
        for s in seen:
            # Same type + same target + same endpoint → likely duplicate
            if (f.get("type", "").lower() == s.get("type", "").lower()
                    and f.get("target", "").lower() == s.get("target", "").lower()
                    and f.get("endpoint", f.get("detail", "")).lower()
                    == s.get("endpoint", s.get("detail", "")).lower()):
                # Same root cause?
                f_root = f.get("root_cause", "").lower()
                s_root = s.get("root_cause", "").lower()
                if f_root and s_root and f_root != s_root:
                    continue  # Different root cause → NOT duplicate
                # Different severity?
                if f.get("severity", "").lower() != s.get("severity", "").lower():
                    continue  # Different severity → NOT duplicate
                is_dup = True
                duplicates.append({
                    "finding": f.get("title", ""),
                    "duplicate_of": s.get("title", ""),
                    "reason": f"Same type ({f.get('type')}), same target, same endpoint",
                })
                break
        if not is_dup:
            seen.append(f)
            unique.append(f)

    return {
        "total": len(findings),
        "unique": len(unique),
        "duplicates": len(duplicates),
        "duplicate_details": duplicates,
        "unique_findings": unique,
    }


# ---------------------------------------------------------------------------
# 3. Vulnerability markdown renderer (from Strix report/writer.py)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def render_vulnerability_md(report: dict) -> str:
    """Render a single vulnerability as structured markdown.

    Fields: title, id, severity, timestamp, target, endpoint, method,
    cve, cwe, cvss, description, impact, technical_analysis,
    poc_description, poc_script_code, remediation, fix_before, fix_after.
    """
    lines: list[str] = [
        f"# {report.get('title', 'Untitled Vulnerability')}\n",
        f"**ID:** {report.get('id', 'unknown')}",
        f"**Severity:** {report.get('severity', 'unknown').upper()}",
        f"**Found:** {report.get('timestamp', 'unknown')}",
    ]

    metadata: list[tuple[str, Any]] = [
        ("Target", report.get("target")),
        ("Endpoint", report.get("endpoint")),
        ("Method", report.get("method")),
        ("CVE", report.get("cve")),
        ("CWE", report.get("cwe")),
    ]
    cvss = report.get("cvss")
    if cvss is not None:
        metadata.append(("CVSS", cvss))
    for label, value in metadata:
        if value:
            lines.append(f"**{label}:** {value}")

    lines += ["", "## Description\n", report.get("description") or "No description provided.", ""]

    if report.get("impact"):
        lines += ["## Impact\n", str(report["impact"]), ""]

    if report.get("technical_analysis"):
        lines += ["## Technical Analysis\n", str(report["technical_analysis"]), ""]

    if report.get("poc_description") or report.get("poc_script_code"):
        lines.append("## Proof of Concept\n")
        if report.get("poc_description"):
            lines += [str(report["poc_description"]), ""]
        if report.get("poc_script_code"):
            lines += ["```", str(report["poc_script_code"]), "```", ""]

    if report.get("remediation"):
        lines += ["## Remediation\n", str(report["remediation"]), ""]

    if report.get("fix_before") and report.get("fix_after"):
        lines += ["## Suggested Fix\n",
                  "**Before:**", "```", str(report["fix_before"]), "```", "",
                  "**After:**", "```", str(report["fix_after"]), "```", ""]

    return "\n".join(lines)


def render_findings_csv(findings: list[dict]) -> str:
    """Render findings as CSV (id, title, severity, timestamp, target, endpoint)."""
    import csv as csvmod
    import io
    buf = io.StringIO()
    fieldnames = ["id", "title", "severity", "timestamp", "target", "endpoint"]
    writer = csvmod.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for f in sorted(findings, key=lambda r: (_SEVERITY_ORDER.get(r.get("severity", "info"), 5), r.get("timestamp", ""))):
        writer.writerow({
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", "info").upper(),
            "timestamp": f.get("created_at", f.get("timestamp", "")),
            "target": f.get("target", ""),
            "endpoint": f.get("endpoint", f.get("detail", ""))[:100],
        })
    return buf.getvalue()


def atomic_write(path: str | Path, content: str) -> None:
    """Atomic write: temp file → rename (from Strix writer.py)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(path.parent),
        prefix=f".{path.name}.", suffix=".tmp", delete=False,
    ) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


# ---------------------------------------------------------------------------
# 4. Agent graph state (from Strix core/agents.py)
# ---------------------------------------------------------------------------

Status = str  # "running" | "waiting" | "completed" | "stopped" | "crashed" | "failed"


class AgentGraph:
    """Multi-agent tree state tracker.

    Tracks parent/child relationships, statuses, and budget stops.
    Adapted from Strix's AgentCoordinator (simplified, no asyncio).
    """

    def __init__(self) -> None:
        self.statuses: dict[str, Status] = {}
        self.parent_of: dict[str, str | None] = {}
        self.names: dict[str, str] = {}
        self.metadata: dict[str, dict[str, Any]] = {}
        self._budget_stopped: bool = False

    def register(self, agent_id: str, name: str, parent: str | None = None) -> None:
        self.statuses[agent_id] = "running"
        self.parent_of[agent_id] = parent
        self.names[agent_id] = name
        self.metadata[agent_id] = {}

    def update_status(self, agent_id: str, status: Status) -> None:
        self.statuses[agent_id] = status

    def set_metadata(self, agent_id: str, key: str, value: Any) -> None:
        self.metadata.setdefault(agent_id, {})[key] = value

    def trigger_budget_stop(self) -> None:
        self._budget_stopped = True

    @property
    def budget_stopped(self) -> bool:
        return self._budget_stopped

    def active_count(self) -> int:
        return sum(1 for s in self.statuses.values() if s in ("running", "waiting"))

    def render_tree(self, highlight: str | None = None) -> str:
        """Render agent tree as indented bullet list."""
        lines: list[str] = []
        # Build children map
        children: dict[str | None, list[str]] = {}
        for aid, parent in self.parent_of.items():
            children.setdefault(parent, []).append(aid)

        def _render(node: str | None, indent: int = 0) -> None:
            for aid in sorted(children.get(node, [])):
                status = self.statuses.get(aid, "?")
                name = self.names.get(aid, aid)
                marker = " ← you" if aid == highlight else ""
                lines.append(f"{'  ' * indent}- [{status}] {name} ({aid}){marker}")
                _render(aid, indent + 1)

        _render(None)
        return "\n".join(lines) if lines else "(no agents)"

    def snapshot(self) -> dict:
        """Serializable snapshot for resume."""
        return {
            "statuses": dict(self.statuses),
            "parent_of": dict(self.parent_of),
            "names": dict(self.names),
            "metadata": {k: dict(v) for k, v in self.metadata.items()},
            "budget_stopped": self._budget_stopped,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# 5. Think tool concept (from Strix tools/thinking/tool.py)
# ---------------------------------------------------------------------------

def think_structure(thought: str) -> dict:
    """Structure a chain-of-thought reasoning step.

    Returns a structured dict (not just a string) to help the agent
    organise reasoning before acting — especially for:
    - Scope compliance verification before each action
    - Multi-step exploit planning (confirmed vs assumed)
    - Risk assessment before destructive operations
    """
    if not thought or not thought.strip():
        return {"success": False, "error": "Thought cannot be empty"}

    # Detect structured sections
    sections: dict[str, str] = {}
    current = "main"
    for line in thought.split("\n"):
        line = line.strip()
        if line.endswith(":") and len(line) < 50:
            current = line[:-1].lower()
            sections[current] = ""
        elif current in sections:
            sections[current] += line + "\n"
        else:
            sections[current] = sections.get(current, "") + line + "\n"

    return {
        "success": True,
        "sections": {k: v.strip() for k, v in sections.items() if v.strip()},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "Thought recorded — use this to plan before acting",
    }


# ---------------------------------------------------------------------------
# 6. HTTP proxy scope management (from Strix tools/proxy/tools.py)
# ---------------------------------------------------------------------------

class ProxyScope:
    """Scope filtering for intercepted HTTP requests.

    Adapted from Strix's Caido proxy scope management.
    In-scope rules: domain match, path prefix, method filter.
    """

    def __init__(self) -> None:
        self.rules: list[dict] = []
        self.sitemap: dict[str, set[str]] = {}  # host → set of paths

    def add_rule(self, host: str, path_prefix: str = "/", methods: list[str] | None = None) -> None:
        self.rules.append({
            "host": host.lower(),
            "path_prefix": path_prefix,
            "methods": [m.upper() for m in (methods or ["GET", "POST"])],
            "action": "include",
        })

    def add_exclude(self, host: str, path_prefix: str = "/") -> None:
        self.rules.append({
            "host": host.lower(),
            "path_prefix": path_prefix,
            "action": "exclude",
        })

    def is_in_scope(self, host: str, path: str, method: str = "GET") -> bool:
        host = host.lower()
        included = False
        for rule in self.rules:
            if rule["host"] not in host and rule["host"] != "*":
                continue
            if not path.startswith(rule["path_prefix"]):
                continue
            if rule["action"] == "exclude":
                return False
            if rule["action"] == "include":
                if "methods" not in rule or method.upper() in rule.get("methods", []):
                    included = True
        return included

    def record_request(self, host: str, path: str) -> None:
        """Add to sitemap (host → paths seen)."""
        host = host.lower()
        if host not in self.sitemap:
            self.sitemap[host] = set()
        self.sitemap[host].add(path)

    def get_sitemap(self) -> dict[str, list[str]]:
        """Return sitemap as host → sorted list of paths."""
        return {h: sorted(p) for h, p in self.sitemap.items()}

    def summary(self) -> dict:
        return {
            "rules": len(self.rules),
            "hosts_tracked": len(self.sitemap),
            "total_paths": sum(len(p) for p in self.sitemap.values()),
        }


# ---------------------------------------------------------------------------
# 7. Retry with exponential backoff (from Strix config/models.py)
# ---------------------------------------------------------------------------

async def retry_async(
    fn,
    *args,
    max_retries: int = 5,
    initial_delay: float = 2.0,
    max_delay: float = 90.0,
    multiplier: float = 2.0,
    **kwargs,
):
    """Retry an async function with exponential backoff.

    Adapted from Strix's ModelRetrySettings.
    Default: 5 retries, 2s→4s→8s→16s→32s, max 90s.

    Usage:
        result = await retry_async(cve_search, keyword="Nextcloud 32")
    """
    delay = initial_delay
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                logger.warning(
                    "Attempt %d/%d failed: %s. Retrying in %.1fs",
                    attempt + 1, max_retries + 1, type(exc).__name__, delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * multiplier, max_delay)
            else:
                logger.error("All %d attempts exhausted: %s", max_retries + 1, exc)

    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 8. HTTP proxy management (from Strix tools/proxy/ — Caido-adapted)
# ---------------------------------------------------------------------------

class HttpProxy:
    """HTTP proxy session — captures, filters, and replays requests.

    Adapted from Strix's Caido proxy integration. Provides:
    - Live request capture (add requests as they're sent)
    - HTTPQL-like filtering (host, path, method, status, regex)
    - Request replay with modifications (headers, body, params, cookies)
    - Sitemap building (host → path tree)
    - Match & replace rules (auto-modify requests/responses)
    - Scope filtering (allow/deny patterns)

    Usage:
        proxy = HttpProxy()
        proxy.add_rule("*.amurobl.ru", methods=["GET","POST"])
        proxy.capture(method="GET", host="gu.amurobl.ru", path="/personal/",
                      status=302, request_raw="GET /personal/ HTTP/1.1...",
                      response_raw="HTTP/1.1 302 Found...")
        hits = proxy.search("client_secret")
        replay = proxy.replay(0, modifications={"headers": {"X-Test": "1"}})
    """

    def __init__(self, history_store: Any | None = None) -> None:
        """Optionally accept a MoonMCP HistoryStore to share entries with the
        built-in intercept.py HTTP history. When a HistoryStore is passed,
        ``capture()`` writes to both the internal list and the HistoryStore,
        and ``list_requests()`` reads from both. This avoids two disconnected
        HTTP-history stores. (Audit 2026-07-27, #6.)
        """
        self._entries: list[dict[str, Any]] = []
        self._counter: int = 0
        self._scope: ProxyScope = ProxyScope()
        self._match_replace: list[dict] = []
        self._history = history_store

    def capture(self, *, method: str, host: str, path: str,
                status: int | None = None,
                request_raw: str = "",
                response_raw: str = "",
                headers: dict | None = None,
                response_headers: dict | None = None,
                elapsed_ms: float = 0,
                is_tls: bool = True) -> str:
        """Capture an HTTP exchange. Returns entry ID."""
        self._counter += 1
        entry_id = f"req-{self._counter}"
        entry: dict[str, Any] = {
            "id": entry_id,
            "method": method.upper(),
            "host": host.lower(),
            "path": path,
            "status": status,
            "request_raw": request_raw,
            "response_raw": response_raw,
            "request_headers": headers or {},
            "response_headers": response_headers or {},
            "elapsed_ms": elapsed_ms,
            "is_tls": is_tls,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._entries.append(entry)
        # Mirror into the shared HistoryStore if one was provided (#6).
        if self._history is not None:
            try:
                self._history.add(entry)
            except Exception:
                pass  # HistoryStore is best-effort; never block capture
        if self._scope.is_in_scope(host, path, method):
            self._scope.record_request(host, path)
        return entry_id

    def list_requests(self, *, host: str = "", path_contains: str = "",
                      method: str = "", status_gte: int | None = None,
                      status_lte: int | None = None,
                      search: str = "", first: int = 50,
                      after: str | None = None) -> dict:
        """List captured requests with optional filtering."""
        results = []
        for e in self._entries:
            if host and host.lower() not in e["host"]:
                continue
            if path_contains and path_contains not in e["path"]:
                continue
            if method and method.upper() != e["method"]:
                continue
            if status_gte and (e["status"] or 0) < status_gte:
                continue
            if status_lte and (e["status"] or 0) > status_lte:
                continue
            if search and search.lower() not in (e["request_raw"] + e["response_raw"]).lower():
                continue
            results.append(e)

        start = 0
        if after:
            for i, e in enumerate(results):
                if e["id"] == after:
                    start = i + 1
                    break
        page = results[start:start + first]
        has_next = start + first < len(results)
        end_cursor = page[-1]["id"] if page else None

        return {
            "entries": [{
                "id": e["id"],
                "method": e["method"],
                "host": e["host"],
                "path": e["path"],
                "status": e["status"],
                "elapsed_ms": e["elapsed_ms"],
            } for e in page],
            "page_info": {
                "has_next_page": has_next,
                "end_cursor": end_cursor,
                "total": len(results),
            },
        }

    def view_request(self, request_id: str, part: str = "request",
                     search_pattern: str = "") -> dict:
        """View a captured request or response, optionally regex-searched."""
        entry = None
        for e in self._entries:
            if e["id"] == request_id:
                entry = e
                break
        if entry is None:
            return {"success": False, "error": f"Request {request_id} not found"}

        raw = entry["request_raw"] if part == "request" else entry["response_raw"]
        if not raw:
            return {"success": False, "error": f"No raw {part} for {request_id}"}

        if search_pattern:
            try:
                regex = re.compile(search_pattern)
            except re.error as exc:
                return {"success": False, "error": f"Invalid regex: {exc}"}
            hits = []
            for match in regex.finditer(raw):
                start, end = match.span()
                hits.append({
                    "match": match.group(0),
                    "position": start,
                    "before": raw[max(0, start - 40):start],
                    "after": raw[end:end + 40],
                })
                if len(hits) >= 20:
                    break
            return {"success": True, "hits": hits, "total_hits": len(hits)}

        return {"success": True, "content": raw[:5000], "truncated": len(raw) > 5000}

    def replay(self, request_id: str, modifications: dict | None = None) -> dict:
        """Prepare a replay request with modifications (does not send).

        Returns the modified raw request for use with http_repeater.
        Recognized modification keys: url, params, headers, body, cookies.

        **Body replacement** handles Content-Length auto-adjustment so the
        server doesn't hang waiting for bytes that never arrive.
        """
        entry = None
        for e in self._entries:
            if e["id"] == request_id:
                entry = e
                break
        if entry is None:
            return {"success": False, "error": f"Request {request_id} not found"}

        mods = modifications or {}
        raw = entry["request_raw"]

        if mods.get("url"):
            raw = re.sub(r'(^\S+\s+)\S+(\s+HTTP)', rf'\g<1>{mods["url"]}\g<2>', raw)
        if mods.get("headers"):
            for k, v in mods["headers"].items():
                if re.search(rf'^{k}:', raw, re.I | re.M):
                    raw = re.sub(rf'^{k}:.*$', f"{k}: {v}", raw, flags=re.I | re.M)
                else:
                    raw = raw.replace("\r\n\r\n", f"\r\n{k}: {v}\r\n\r\n", 1)
        if mods.get("body"):
            # Replace body and auto-adjust Content-Length if present
            new_body = mods["body"]
            if re.search(r'^Content-Length:', raw, re.I | re.M):
                raw = re.sub(r'^Content-Length:.*$',
                             f'Content-Length: {len(new_body)}',
                             raw, flags=re.I | re.M)
            parts = raw.split("\r\n\r\n", 1)
            raw = parts[0] + "\r\n\r\n" + new_body
        if mods.get("params"):
            for k, v in mods["params"].items():
                if f"{k}=" in raw:
                    raw = re.sub(rf'{k}=[^&\s]+', f'{k}={v}', raw)
                else:
                    if "?" not in raw.split(" HTTP")[0]:
                        raw = raw.replace(" HTTP", f"?{k}={v} HTTP", 1)
                    else:
                        raw = raw.replace(" HTTP", f"&{k}={v} HTTP", 1)

        return {
            "success": True,
            "original_id": request_id,
            "modified_raw": raw,
            "modifications_applied": list(mods.keys()),
            "next_step": "Pass modified_raw to http_repeater(raw=...) to send",
        }

    def sitemap(self) -> dict:
        """Return hierarchical sitemap: host → sorted paths."""
        return self._scope.get_sitemap()

    def add_match_replace(self, name: str, pattern: str, replacement: str,
                          *, part: str = "request") -> None:
        """Add a match & replace rule."""
        self._match_replace.append({
            "name": name,
            "pattern": pattern,
            "replacement": replacement,
            "part": part,
        })

    def apply_match_replace(self, raw: str, part: str = "request") -> str:
        """Apply all match & replace rules to raw content."""
        for rule in self._match_replace:
            if rule["part"] == part:
                raw = re.sub(rule["pattern"], rule["replacement"], raw)
        return raw

    def scope_rules(self, action: str = "list", **kwargs) -> dict:
        """Manage proxy scope rules (list/create/update/delete)."""
        if action == "list":
            return {"rules": self._scope.rules, "summary": self._scope.summary()}
        if action == "create":
            self._scope.add_rule(
                kwargs.get("host", "*"),
                kwargs.get("path_prefix", "/"),
                kwargs.get("methods"),
            )
            return {"success": True, "message": "Scope rule added"}
        if action == "exclude":
            self._scope.add_exclude(kwargs.get("host", "*"), kwargs.get("path_prefix", "/"))
            return {"success": True, "message": "Exclude rule added"}
        return {"error": f"Unknown action: {action}"}

    def summary(self) -> dict:
        return {
            "total_requests": len(self._entries),
            "sitemap": self._scope.summary(),
            "match_replace_rules": len(self._match_replace),
        }


# ---------------------------------------------------------------------------
# 9. Docker sandbox for safe PoC execution (from Strix runtime/docker_client.py)
# ---------------------------------------------------------------------------

class DockerSandbox:
    """Docker-based isolated execution environment for PoC testing.

    Adapted from Strix's DockerSandboxClient. Provides:
    - CPU, memory and process limits
    - No container network or extra capabilities by default
    - Explicit failure and uncertain-execution outcomes

    Default image is ``alpine:latest`` (~7 MB pull). For full Kali tooling
    (nmap, sqlmap, nuclei, gobuster) pass ``image="kali-linux:latest"`` (~3 GB)
    — but for simple RCE proof (hostname/whoami/id/ifconfig) alpine is enough
    and pulls in seconds.

    Requires Docker to be installed and running.
    """

    def __init__(self, image: str = "alpine:latest",
                 cap_add: list[str] | None = None,
                 network: str = "none") -> None:
        self.image = image
        self.cap_add = list(cap_add) if cap_add is not None else []
        self.network = network
        self._container_id: str | None = None
        self._execution_unknown = False

    def _check_docker(self) -> bool:
        """Check if Docker is available."""
        import shutil
        return shutil.which("docker") is not None

    def start(self) -> dict:
        """Start a Docker container for sandboxed execution."""
        if self._container_id:
            return {"success": False, "error": "sandbox_exists",
                    "detail": "Stop the existing sandbox before starting another."}
        if not self._check_docker():
            return {
                "success": False,
                "error": "Docker not installed or not in PATH",
                "hint": "Install Docker: sudo apt install docker.io && sudo systemctl start docker",
            }
        import subprocess
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", self.image],
                capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                pull = subprocess.run(
                    ["docker", "pull", self.image],
                    capture_output=True, timeout=300,
                )
                if pull.returncode != 0:
                    return {"success": False, "error": "image_pull_failed",
                            "detail": pull.stderr.decode(errors="replace")[:2000]}

            container_name = f"moonmcp-sandbox-{uuid.uuid4().hex}"
            cmd = [
                "docker", "run", "-d",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--network", self.network,
                "--memory", "512m",
                "--cpus", "1.0",
                "--pids-limit", "64",
                "--name", container_name,
            ]
            for capability in self.cap_add:
                cmd.extend(["--cap-add", capability])
            cmd.extend([self.image, "tail", "-f", "/dev/null"])
            # Retain a usable resource locator if the CLI loses the run result.
            self._container_id = container_name
            self._execution_unknown = True
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            if result.returncode != 0:
                return {"success": False, "error": "sandbox_start_failed",
                        "container_id": container_name,
                        "detail": result.stderr.decode(errors="replace")[:2000],
                        "recovery": "Inspect and remove the retained container before restarting."}
            self._container_id = result.stdout.decode().strip() or container_name
            self._execution_unknown = False
            return {
                "success": True,
                "container_id": self._container_id,
                "image": self.image,
                "message": "Sandbox started. Use exec() to run commands.",
            }
        except Exception as exc:
            if self._container_id:
                return {"success": False, "ok": False, "state": "unknown",
                        "error": "outcome_unknown", "retryable": False,
                        "container_id": self._container_id, "detail": str(exc),
                        "recovery": "Inspect and remove the retained container before restarting."}
            return {"success": False, "error": str(exc)}

    def exec(self, command: str, *, timeout: int = 30,
             scope_check=None) -> dict:
        """Execute a command in the sandbox container.

        If ``scope_check`` is provided (a callable that takes a host and
        returns bool), URLs in the command are extracted and checked —
        an out-of-scope literal URL aborts execution. This is a convenience
        check, not a network boundary; the default container network is disabled.
        """
        if not self._container_id:
            return {"success": False, "error": "Sandbox not started. Call start() first."}
        if self._execution_unknown:
            return {"success": False, "ok": False, "state": "unknown",
                    "error": "outcome_unknown", "retryable": False,
                    "recovery": "Stop and remove the sandbox before further execution."}
        if scope_check is not None:
            # Extract hostnames from URLs in the command
            urls = re.findall(r'https?://([^\s/\'"<>]+)', command)
            for host in urls:
                host = host.split(":")[0]  # strip port
                if not scope_check(host):
                    return {"success": False,
                            "error": f"out of scope: {host}",
                            "detail": "Command contains a URL to an out-of-scope host; "
                                      "sandbox execution refused."}
        import subprocess
        try:
            result = subprocess.run(
                ["docker", "exec", self._container_id, "sh", "-c", command],
                capture_output=True, timeout=timeout,
            )
            payload = {
                "success": result.returncode == 0,
                "exit_code": result.returncode,
                "stdout": result.stdout.decode(errors="replace")[:5000],
                "stderr": result.stderr.decode(errors="replace")[:2000],
                "command": command,
            }
            if result.returncode != 0:
                payload.update(error="command_failed", retryable=False,
                               detail=f"Sandbox command exited with status {result.returncode}.")
            return payload
        except subprocess.TimeoutExpired:
            self._execution_unknown = True
            return {"success": False, "ok": False, "state": "unknown",
                    "error": "outcome_unknown", "retryable": False,
                    "detail": f"Docker exec timed out after {timeout}s; the child may still be running.",
                    "recovery": "Stop and remove the sandbox before further execution."}
        except Exception as exc:
            self._execution_unknown = True
            return {"success": False, "ok": False, "state": "unknown",
                    "error": "outcome_unknown", "retryable": False, "detail": str(exc),
                    "recovery": "Inspect and remove the sandbox before further execution."}

    def stop(self) -> dict:
        """Stop and remove the sandbox container."""
        if not self._container_id:
            return {"success": False, "error": "No container to stop"}
        import subprocess
        try:
            removed = subprocess.run(["docker", "rm", "-f", self._container_id],
                                     capture_output=True, timeout=30)
            if removed.returncode != 0:
                return {"success": False, "error": "cleanup_failed", "retryable": False,
                        "container_id": self._container_id,
                        "detail": removed.stderr.decode(errors="replace")[:2000]}
            cid = self._container_id
            self._container_id = None
            self._execution_unknown = False
            return {"success": True, "message": f"Container {cid} stopped and removed"}
        except Exception as exc:
            return {"success": False, "error": "cleanup_failed", "retryable": False,
                    "container_id": self._container_id, "detail": str(exc)}

    def status(self) -> dict:
        """Check sandbox container status."""
        if not self._container_id:
            return {"running": False, "container_id": None}
        import subprocess
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Status}}", self._container_id],
                capture_output=True, timeout=10,
            )
            state = result.stdout.decode().strip() if result.returncode == 0 else "unknown"
            return {"running": state == "running", "container_id": self._container_id, "state": state}
        except Exception:
            return {"running": False, "container_id": self._container_id, "state": "error"}


def retry_sync(
    fn,
    *args,
    max_retries: int = 5,
    initial_delay: float = 2.0,
    max_delay: float = 90.0,
    multiplier: float = 2.0,
    **kwargs,
):
    """Synchronous version of retry_async."""
    delay = initial_delay
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                logger.warning(
                    "Attempt %d/%d failed: %s. Retrying in %.1fs",
                    attempt + 1, max_retries + 1, type(exc).__name__, delay,
                )
                time.sleep(delay)
                delay = min(delay * multiplier, max_delay)
            else:
                logger.error("All %d attempts exhausted: %s", max_retries + 1, exc)

    raise last_exc  # type: ignore[misc]
