"""One policy declaration drives discovery, profile views and managed dispatch."""

from dataclasses import FrozenInstanceError

import pytest

from moonmcp import agent_tools, catalog, execution, registry, sdk, server, toolspec
from moonmcp.config import Settings


def test_registered_tools_have_one_shared_policy():
    live = sdk.registered_tools(server.mcp)
    assert live.keys() == registry.POLICIES.keys()
    specs = toolspec.registry(Settings())
    for name, declaration in registry.POLICIES.items():
        assert specs[name].family == catalog.TOOL_FAMILY[name] == declaration.family
        assert specs[name].aliases == declaration.aliases
        assert bool(specs[name].read_only) == declaration.read_only
        assert execution.request_accounting(name) == declaration.accounting
        assert (name in execution.PURE_REFERENCE_TOOLS) == declaration.static_reference
        assert (name in execution.PUBLIC_RESEARCH_TOOLS) == declaration.public_research
        assert (name in agent_tools.COMPACT_TOOLS) == declaration.compact
        assert (name in catalog._ALWAYS_ON) == declaration.orientation


def test_unknown_tool_does_not_gain_execution_privileges_by_naming():
    for name in ("new_reference_info", "http_new_probe", "unknown_tool"):
        declaration = registry.policy(name)
        assert declaration.family == "uncategorized"
        assert execution.request_accounting(name) == "unmetered"
        assert not declaration.static_reference and not declaration.read_only
        assert not declaration.public_research and not declaration.compact


def test_policy_cannot_be_mutated_during_an_execution():
    with pytest.raises(TypeError):
        registry.POLICIES["http_probe"] = registry.policy("scope_list")
    with pytest.raises(FrozenInstanceError):
        registry.POLICIES["http_probe"].accounting = "local"


def test_unreviewed_transports_stay_outside_http_accounting():
    for name in ("dns_lookup", "tls_inspect", "browser_open", "run_scanner"):
        assert registry.policy(name).accounting == "unmetered"
    for name in ("http_probe", "http_repeater", "web_read"):
        assert registry.policy(name).accounting == "http_client"
