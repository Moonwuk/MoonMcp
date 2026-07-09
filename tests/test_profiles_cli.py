"""Tool-exposure profiles + the `moonmcp call` / `moonmcp tools` CLI bridge."""

import json

from moonmcp import catalog as cat
from moonmcp.__main__ import main

ALL = set(cat.TOOL_FAMILY)  # every registered tool is categorized (see test_catalog)


def test_no_inputs_exposes_everything():
    assert cat.select_profile(ALL) == ALL


def test_strix_profile_hides_heavy_families_keeps_brain():
    allowed = cat.select_profile(ALL, profile="strix")
    # Strix has its own scanners/proxy/orchestrator — those are hidden.
    for hidden in ("port_scan", "vuln_scan", "content_discovery", "run_scanner",
                   "http_repeater", "intruder", "probe_batch"):
        assert hidden not in allowed, hidden
    # But it gains MoonMCP's reference brain + shared memory + cheap recon.
    for kept in ("injection_info", "technique_info", "memory_search", "add_finding",
                 "fingerprint", "cve_search", "scope_list"):
        assert kept in allowed, kept


def test_knowledge_profile_is_offline_reference_plus_memory():
    allowed = cat.select_profile(ALL, profile="knowledge")
    assert "injection_info" in allowed and "memory_search" in allowed
    assert "http_probe" not in allowed and "port_scan" not in allowed
    # Orientation tools are always reachable.
    assert {"server_status", "tool_catalog", "scope_list"} <= allowed


def test_expose_is_a_whitelist():
    allowed = cat.select_profile(ALL, expose=["http_probe"])
    assert "http_probe" in allowed
    assert "port_scan" not in allowed
    assert {"server_status", "tool_catalog", "scope_list"} <= allowed  # always-on


def test_hide_removes_a_family():
    allowed = cat.select_profile(ALL, hide=["intrusive"])
    assert "port_scan" not in allowed and "vuln_scan" not in allowed
    assert "http_probe" in allowed  # everything else stays


def test_unknown_profile_falls_back_to_all():
    assert cat.select_profile(ALL, profile="does-not-exist") == ALL


def test_cli_tools_json(capsys):
    rc = main(["tools", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    names = {t["name"] for t in data}
    assert {"injection_info", "http_probe", "memory_search"} <= names


def test_cli_call_json_arg(capsys):
    rc = main(["call", "injection_info", "--json", '{"injection_class": "ssti"}'])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["id"] == "ssti"


def test_cli_call_kv_arg(capsys):
    rc = main(["call", "injection_info", "--arg", "injection_class=ssti"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["id"] == "ssti"


def test_cli_call_unknown_tool(capsys):
    rc = main(["call", "no_such_tool"])
    assert rc == 2
    assert json.loads(capsys.readouterr().out)["error"] == "unknown_tool"


def test_cli_call_bad_json(capsys):
    rc = main(["call", "injection_info", "--json", "{not json"])
    assert rc == 2
    assert json.loads(capsys.readouterr().out)["error"] == "bad_json"
