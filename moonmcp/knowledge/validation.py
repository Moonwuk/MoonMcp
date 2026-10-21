"""Offline schema checks for the five referenced knowledge catalogs.

Version checks are used by query loaders; full validation is an explicit CI or
maintainer operation. It never evaluates payloads, follows references or sends
network requests. Existing Python data remains the storage format.
"""

from __future__ import annotations

import importlib
import json
import re
from collections.abc import Mapping

SCHEMA_VERSION = 1
_COMMON = {"id": str, "name": str, "summary": str}
_STRINGS = "strings"
_ROWS = "rows"
_SCHEMAS: dict[str, dict[str, object]] = {
    "INJECTIONS": {**_COMMON, "aliases": _STRINGS, "cwe": _STRINGS,
                   "owasp": str, "severity": str, "root_causes": _STRINGS,
                   "contexts": _STRINGS, "detection_payloads": _ROWS,
                   "signatures": _ROWS, "by_technology": _ROWS,
                   "false_positives": _STRINGS, "remediation": _STRINGS,
                   "references": _STRINGS},
    "TECHNIQUES": {**_COMMON, "category": str, "languages": _STRINGS,
                   "severity": str, "technique": str, "affected_context": str,
                   "detection_indicators": _STRINGS, "cve": _STRINGS,
                   "poc_references": _STRINGS, "research_references": _STRINGS},
    "SERVER_SIDE_VULNS": {**_COMMON, "category": str, "popularity": str,
                          "root_cause": str, "where_it_breaks": str,
                          "waf_notes": str, "references": _STRINGS,
                          "detection": "text_or_strings"},
    "ROOT_CAUSES": {**_COMMON, "why_it_recurs": str, "systemic_fix": str,
                    "derived_vuln_classes": _STRINGS, "references": _STRINGS},
    "VULN_TOOLS": {**_COMMON, "category": str, "target": str, "url": str,
                   "usage_note": str},
    "PRIVESC": {**_COMMON, "platform": str, "category": str, "severity": str,
                "technique": str, "prerequisites": _STRINGS,
                "enumeration": _STRINGS, "detection_indicators": _STRINGS,
                "tools": _STRINGS, "cve": _STRINGS, "mitigation": _STRINGS,
                "poc_references": _STRINGS, "research_references": _STRINGS},
    "PRIVESC_TOOLS": {**_COMMON, "platform": str, "category": str,
                      "usage_note": str, "language": str, "url": str},
    "WAF_ENTRIES": {**_COMMON, "category": str, "detail": str,
                    "indicator": str, "applies_to": _STRINGS,
                    "references": _STRINGS},
}
_CATALOGS = {
    "injections": ("injections_data", ("INJECTIONS",)),
    "techniques": ("techniques_data", ("TECHNIQUES",)),
    "vulns": ("vulns_data", ("SERVER_SIDE_VULNS", "ROOT_CAUSES", "VULN_TOOLS")),
    "privesc": ("privesc_data", ("PRIVESC", "PRIVESC_TOOLS")),
    "waf": ("waf_kb_data", ("WAF_ENTRIES",)),
}


def require_schema_version(catalog: str, version: object) -> None:
    """Reject a missing, boolean or unsupported catalog schema version."""
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValueError(f"{catalog}: unsupported knowledge schema version {version!r}; "
                         f"expected {SCHEMA_VERSION}")


def _matches(value: object, expected: object) -> bool:
    if expected is str:
        return isinstance(value, str)
    if expected == "text_or_strings" and isinstance(value, str):
        return True
    if not isinstance(value, list):
        return False
    kind = dict if expected == _ROWS else str
    return all(isinstance(item, kind) for item in value)


def _fields(row: dict, schema: dict, path: str, errors: list[str]) -> None:
    for field, expected in schema.items():
        if field not in row:
            errors.append(f"{path}.{field}: required field is missing")
        elif not _matches(row[field], expected):
            label = "string" if expected is str else str(expected)
            errors.append(f"{path}.{field}: expected {label}")
        elif field in _COMMON and not row[field].strip():
            errors.append(f"{path}.{field}: must not be empty")


def _injection_details(row: dict, path: str, errors: list[str]) -> None:
    for field, schema in (
        ("detection_payloads", {"payload": str, "technique": str, "expected_indicator": str}),
        ("signatures", {"type": str, "value": str, "meaning": str, "technology": str}),
        ("by_technology", {"technology": str, "notes": str,
                           "payloads": _STRINGS, "signatures": _STRINGS}),
    ):
        rows = row.get(field)
        if not isinstance(rows, list):
            continue  # the enclosing schema already records the shape error
        for i, item in enumerate(rows):
            if not isinstance(item, dict):
                continue
            location = f"{path}.{field}[{i}]"
            _fields(item, schema, location, errors)
            if field != "signatures":
                continue
            if not isinstance(item.get("type"), str) or item["type"] not in {"error", "regex", "behavioral"}:
                errors.append(f"{location}.type: unsupported signature type")
            if item.get("type") == "regex" and isinstance(item.get("value"), str):
                try:
                    re.compile(item["value"], re.IGNORECASE)
                except re.error as exc:
                    errors.append(f"{location}.value: invalid regex ({exc})")


def validate_catalog(catalog: str, namespace: Mapping[str, object] | None = None) -> dict:
    """Validate installed data or an explicit namespace without modifying it.

    Unknown additive fields are permitted. The existing six concise vulnerability
    entries may omit severity/tools and express detection as a single string.
    ``derived_vuln_classes`` contains descriptive labels, not vulnerability IDs.
    """
    if catalog not in _CATALOGS:
        raise ValueError(f"Unknown knowledge catalog: {catalog}")
    module_name, collections = _CATALOGS[catalog]
    if namespace is None:
        namespace = vars(importlib.import_module(f"{__package__}.{module_name}"))
    errors: list[str] = []
    try:
        require_schema_version(catalog, namespace.get("SCHEMA_VERSION"))
    except ValueError as exc:
        errors.append(str(exc))
    counts = {}
    for collection in collections:
        rows = namespace.get(collection)
        if not isinstance(rows, list):
            errors.append(f"{collection}: expected a list of objects")
            counts[collection] = 0
            continue
        counts[collection] = len(rows)
        seen = set()
        for i, row in enumerate(rows):
            path = f"{collection}[{i}]"
            if not isinstance(row, dict):
                errors.append(f"{path}: expected an object")
                continue
            _fields(row, _SCHEMAS[collection], path, errors)
            ident = row.get("id")
            if isinstance(ident, str):
                if ident in seen:
                    errors.append(f"{path}.id: duplicate ID {ident!r}")
                seen.add(ident)
            if "severity" in row and (not isinstance(row["severity"], str)
                                      or row["severity"] not in {"critical", "high", "medium", "low", "info"}):
                errors.append(f"{path}.severity: unsupported severity")
            if collection == "SERVER_SIDE_VULNS":
                for field in ("tools", "real_world"):
                    if field in row and not _matches(row[field], _STRINGS):
                        errors.append(f"{path}.{field}: expected strings")
                if not isinstance(row.get("popularity"), str) or row["popularity"] not in {"common", "uncommon", "rare"}:
                    errors.append(f"{path}.popularity: unsupported popularity")
            if collection == "INJECTIONS":
                _injection_details(row, path, errors)
    if catalog == "vulns":
        roots = namespace.get("ROOT_CAUSES")
        entries = namespace.get("SERVER_SIDE_VULNS")
        if isinstance(roots, list) and isinstance(entries, list):
            known = {r["id"] for r in roots if isinstance(r, dict) and isinstance(r.get("id"), str)}
            for i, entry in enumerate(entries):
                if isinstance(entry, dict) and isinstance(entry.get("root_cause"), str):
                    if entry["root_cause"] not in known:
                        errors.append(f"SERVER_SIDE_VULNS[{i}].root_cause: dangling reference "
                                      f"{entry['root_cause']!r}")
    return {"catalog": catalog, "schema_version": namespace.get("SCHEMA_VERSION"),
            "collections": counts, "ok": not errors, "errors": errors}


def validate_all() -> dict:
    """Return a deterministic, JSON-serializable report for every catalog."""
    reports = [validate_catalog(name) for name in _CATALOGS]
    return {"schema_version": SCHEMA_VERSION,
            "ok": all(report["ok"] for report in reports), "catalogs": reports}


def main() -> int:
    report = validate_all()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
