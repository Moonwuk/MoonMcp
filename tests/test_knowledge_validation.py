"""Validate data contracts without executing payloads or fetching references."""

import copy
import importlib
import json

import pytest

from moonmcp.knowledge import validation

_CATALOGS = {
    "injections": ("injections_data", "INJECTIONS"),
    "techniques": ("techniques_data", "TECHNIQUES"),
    "vulns": ("vulns_data", "SERVER_SIDE_VULNS"),
    "privesc": ("privesc_data", "PRIVESC"),
    "waf": ("waf_kb_data", "WAF_ENTRIES"),
}


def namespace(catalog):
    module, _ = _CATALOGS[catalog]
    values = vars(importlib.import_module("moonmcp.knowledge." + module))
    return copy.deepcopy({key: value for key, value in values.items()
                          if not key.startswith("_") and key != "annotations"})


def test_installed_catalogs_validate_without_network(monkeypatch):
    import socket

    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: pytest.fail("network access"))
    result = validation.validate_all()
    assert result["ok"]
    assert len(result["catalogs"]) == 5
    assert all(report["schema_version"] == 1 and not report["errors"]
               for report in result["catalogs"])
    assert sum(sum(report["collections"].values()) for report in result["catalogs"]) >= 400
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize("catalog", _CATALOGS)
@pytest.mark.parametrize("version", [None, True, "1", 0, 2])
def test_rejects_missing_boolean_or_unsupported_versions(catalog, version):
    data = namespace(catalog)
    if version is None:
        del data["SCHEMA_VERSION"]
    else:
        data["SCHEMA_VERSION"] = version
    report = validation.validate_catalog(catalog, data)
    assert not report["ok"]
    assert any("unsupported knowledge schema version" in error for error in report["errors"])
    with pytest.raises(ValueError, match="unsupported knowledge schema version"):
        validation.require_schema_version(catalog, version)


@pytest.mark.parametrize("catalog", _CATALOGS)
def test_duplicate_ids_are_rejected_per_collection(catalog):
    data = namespace(catalog)
    collection = _CATALOGS[catalog][1]
    data[collection].append(copy.deepcopy(data[collection][0]))
    report = validation.validate_catalog(catalog, data)
    assert not report["ok"]
    assert any("duplicate ID" in error for error in report["errors"])


@pytest.mark.parametrize("loader", ["injections", "techniques", "vulns", "privesc", "waf_kb"])
def test_query_loaders_reject_unsupported_data_versions(loader, monkeypatch):
    data = importlib.import_module(f"moonmcp.knowledge.{loader}_data")
    query = importlib.import_module(f"moonmcp.knowledge.{loader}")
    original = data.SCHEMA_VERSION
    monkeypatch.setattr(data, "SCHEMA_VERSION", 2)
    try:
        with pytest.raises(ValueError, match="unsupported knowledge schema version"):
            importlib.reload(query)
    finally:
        monkeypatch.setattr(data, "SCHEMA_VERSION", original)
        importlib.reload(query)


@pytest.mark.parametrize("field,value", [("id", []), ("name", None), ("summary", " "),
                                         ("aliases", "sql"), ("severity", ["high"]),
                                         ("signatures", ["not-an-object"])])
def test_malformed_required_fields_are_reported_without_crashing(field, value):
    data = namespace("injections")
    data["INJECTIONS"][0][field] = value
    report = validation.validate_catalog("injections", data)
    assert not report["ok"]
    assert any(f".{field}:" in error for error in report["errors"])


def test_malformed_collections_and_missing_fields_are_reported():
    data = namespace("vulns")
    data["VULN_TOOLS"] = {}
    del data["ROOT_CAUSES"][0]["summary"]
    data["SERVER_SIDE_VULNS"].append(None)
    report = validation.validate_catalog("vulns", data)
    assert not report["ok"]
    assert "VULN_TOOLS: expected a list of objects" in report["errors"]
    assert any("summary: required field is missing" in error for error in report["errors"])
    assert any("expected an object" in error for error in report["errors"])


def test_invalid_regex_and_nested_signature_type_are_rejected():
    data = namespace("injections")
    signatures = data["INJECTIONS"][0]["signatures"]
    signatures[0].update(type="regex", value="[")
    signatures[1]["type"] = []
    data["INJECTIONS"][0]["by_technology"][0]["payloads"] = [None]
    report = validation.validate_catalog("injections", data)
    assert not report["ok"]
    assert any("invalid regex" in error for error in report["errors"])
    assert any("unsupported signature type" in error for error in report["errors"])
    assert any("payloads: expected strings" in error for error in report["errors"])


def test_root_cause_foreign_keys_must_resolve():
    data = namespace("vulns")
    data["SERVER_SIDE_VULNS"][0]["root_cause"] = "misspelled-root-cause"
    report = validation.validate_catalog("vulns", data)
    assert not report["ok"]
    assert any("dangling reference" in error for error in report["errors"])


def test_legacy_vulnerability_forms_and_additive_fields_remain_compatible():
    data = namespace("vulns")
    row = data["SERVER_SIDE_VULNS"][0]
    row["detection"] = "A concise detection note"
    row.pop("severity", None)
    row.pop("tools", None)
    row["new_optional_metadata"] = {"note": "does not change version-1 required fields"}
    assert validation.validate_catalog("vulns", data)["ok"]


def test_cli_reports_valid_data_and_nonzero_failure(monkeypatch, capsys):
    assert validation.main() == 0
    assert json.loads(capsys.readouterr().out)["ok"]
    monkeypatch.setattr(validation, "validate_all", lambda: {"ok": False, "catalogs": []})
    assert validation.main() == 1
    assert not json.loads(capsys.readouterr().out)["ok"]


def test_unknown_catalog_is_an_explicit_input_error():
    with pytest.raises(ValueError, match="Unknown knowledge catalog"):
        validation.validate_catalog("unknown", {})
