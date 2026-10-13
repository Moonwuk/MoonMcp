"""Project operator skills stay concise, discoverable and aligned with run tools."""

from pathlib import Path

import pytest

from moonmcp import server as srv

ROOT = Path(__file__).parents[1]
ADAPTED = {
    "assessment-planning": {
        "run_start", "run_task_add", "run_coverage_update", "memory_brief",
    },
    "systematic-validation": {
        "run_artifact_add", "run_coverage_update", "run_usage", "confirm_finding",
    },
    "run-coordination": {
        "run_status", "run_next", "run_task_update", "run_finish",
    },
}


@pytest.mark.parametrize(("name", "tools"), ADAPTED.items())
def test_adapted_skill_is_valid_and_references_registered_tools(name, tools):
    path = ROOT / ".claude" / "skills" / name / "SKILL.md"
    text = path.read_text(encoding="utf-8")
    assert text.startswith(f"---\nname: {name}\ndescription: Use when")
    assert "TODO" not in text and len(text.splitlines()) < 180
    registered = {tool.name for tool in srv.mcp._tool_manager.list_tools()}
    assert tools <= registered
    assert all(f"`{tool}" in text for tool in tools)


@pytest.mark.parametrize("name", ADAPTED)
def test_adapted_skill_has_matching_ui_metadata(name):
    metadata = ROOT / ".claude" / "skills" / name / "agents" / "openai.yaml"
    text = metadata.read_text(encoding="utf-8")
    assert f"${name}" in text
    assert "display_name:" in text and "short_description:" in text
