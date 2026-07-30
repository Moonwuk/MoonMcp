"""Config env parsing: numeric clamping and a single-source default User-Agent."""

from moonmcp.config import _DEFAULT_USER_AGENT, Settings, _env_float, _env_int, load_settings


def test_env_float_clamps_below_minimum(monkeypatch):
    monkeypatch.setenv("MM_T", "-5")
    assert _env_float("MM_T", 10.0, minimum=0.1) == 0.1
    monkeypatch.setenv("MM_T", "3.5")
    assert _env_float("MM_T", 10.0, minimum=0.1) == 3.5
    # unset / unparseable fall back to the default (no clamp applied to the default)
    monkeypatch.delenv("MM_T", raising=False)
    assert _env_float("MM_T", 10.0, minimum=0.1) == 10.0
    monkeypatch.setenv("MM_T", "not-a-number")
    assert _env_float("MM_T", 10.0, minimum=0.1) == 10.0


def test_env_int_clamps_below_minimum(monkeypatch):
    monkeypatch.setenv("MM_I", "0")
    assert _env_int("MM_I", 20, minimum=1) == 1
    monkeypatch.setenv("MM_I", "8")
    assert _env_int("MM_I", 20, minimum=1) == 8


def test_load_settings_clamps_nonsensical_numerics(monkeypatch):
    monkeypatch.setenv("MOONMCP_TIMEOUT", "-5")
    monkeypatch.setenv("MOONMCP_MAX_CONCURRENCY", "0")
    monkeypatch.setenv("MOONMCP_MAX_REDIRECTS", "-3")
    monkeypatch.setenv("MOONMCP_EXTERNAL_TIMEOUT", "-1")
    s = load_settings()
    assert s.timeout >= 0.1
    assert s.max_concurrency >= 1
    assert s.max_redirects >= 0
    assert s.external_timeout >= 1.0


def test_user_agent_is_single_source(monkeypatch):
    assert Settings().user_agent == _DEFAULT_USER_AGENT
    monkeypatch.delenv("MOONMCP_USER_AGENT", raising=False)
    assert load_settings().user_agent == _DEFAULT_USER_AGENT
    monkeypatch.setenv("MOONMCP_USER_AGENT", "custom/1.0")
    assert load_settings().user_agent == "custom/1.0"
