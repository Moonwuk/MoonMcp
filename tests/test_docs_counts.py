"""README / docs numbers must match reality.

Guards the drift the review found: 166-vs-158-vs-169 tools, "190+" vs the real
~800 tests, understated KB sizes, and 8 undocumented tools. If a future change
adds a tool or KB entry, these fail until the docs are updated.
"""

import re
from pathlib import Path

from moonmcp import server as srv
from moonmcp.knowledge.injections_data import INJECTIONS
from moonmcp.knowledge.privesc_data import PRIVESC
from moonmcp.knowledge.techniques_data import TECHNIQUES
from moonmcp.knowledge.vulns_data import SERVER_SIDE_VULNS
from moonmcp.knowledge.waf_kb_data import WAF_ENTRIES

_ROOT = Path(__file__).resolve().parent.parent
README = (_ROOT / "README.md").read_text()


def _tool_names():
    return {t.name for t in srv.mcp._tool_manager.list_tools()}


def _stated(pattern: str) -> int:
    m = re.search(pattern, README)
    assert m, f"README pattern not found (docs drifted?): {pattern}"
    return int(m.group(1))


def test_every_registered_tool_is_documented_in_readme():
    missing = sorted(n for n in _tool_names() if n not in README)
    assert not missing, f"tools registered but absent from README: {missing}"


def test_readme_headline_tool_resource_prompt_counts_match_live():
    n_tools = len(_tool_names())
    n_prompts = len(srv.mcp._prompt_manager.list_prompts())
    n_resources = len(srv.mcp._resource_manager.list_resources())
    m = re.search(r"\*\*(\d+) tools\*\*, \*\*(\d+) resources\*\* and \*\*(\d+) operator prompts\*\*",
                  README)
    assert m, "headline tool/resource/prompt sentence not found in README"
    assert (int(m.group(1)), int(m.group(2)), int(m.group(3))) == (n_tools, n_resources, n_prompts)
    assert _stated(r"FastMCP server: (\d+) tools") == n_tools   # architecture block agrees


def test_readme_knowledge_base_counts_match_live():
    assert _stated(r"\*\*(\d+) classes\*\* \(\d+ detection payloads") == len(INJECTIONS)
    assert _stated(r"\*\*(\d+) classes\*\* \(popular") == len(SERVER_SIDE_VULNS)
    assert _stated(r"\*\*(\d+) entries\*\*") == len(WAF_ENTRIES)
    assert _stated(r"\*\*(\d+) techniques\*\* across") == len(TECHNIQUES)
    assert _stated(r"\*\*(\d+) techniques\*\* \(Linux") == len(PRIVESC)


def test_readme_test_count_is_not_overclaimed():
    # "N+ tests" must not exceed the real number of test functions.
    stated = _stated(r"(\d+)\+ tests")
    actual = sum(len(re.findall(r"^\s*(?:async )?def test_", p.read_text(), re.M))
                 for p in (_ROOT / "tests").glob("test_*.py"))
    assert stated <= actual, f"README claims {stated}+ tests but only {actual} exist"
