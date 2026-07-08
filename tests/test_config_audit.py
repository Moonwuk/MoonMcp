"""Tests for the configuration-file analyzer."""

import pytest

from moonmcp import server as srv
from moonmcp.recon.config_audit import analyze_config, detect_format


def _issues(audit):
    return {f.issue for f in audit.findings}


def test_detect_format():
    assert detect_format("A=1\nB=2", ".env") == "dotenv"
    assert detect_format('{"a":1}', "x.json") == "json"
    assert detect_format("[sec]\nk=v") == "ini"
    assert detect_format("<config><add key='a' value='b'/></config>", "web.config") == "xml"
    assert detect_format("a:\n  b: 1", "c.yaml") == "yaml"


def test_dotenv_flags_all_the_things():
    env = (
        "APP_ENV=production\nDEBUG=true\nDB_PASSWORD=Sup3rS3cret!\n"
        "DATABASE_URL=postgres://admin:hunter2@db.internal:5432/app\n"
        "CORS_ALLOWED_ORIGINS=*\nSSL_VERIFY=false\nHOST=0.0.0.0\n"
    )
    a = analyze_config(env, filename=".env")
    assert a.format == "dotenv"
    assert a.setting_count == 7
    issues = _issues(a)
    assert "exposed credential" in issues
    assert "credentials in connection string" in issues
    assert "TLS verification disabled" in issues
    assert "debug enabled" in issues
    assert "wildcard CORS / allowed hosts" in issues
    assert "bound to all interfaces" in issues
    # secret value is redacted
    pw = next(s for s in a.settings if s.key == "DB_PASSWORD")
    assert pw.sensitive and "Sup3rS3cret" not in pw.value


def test_json_nested_flatten_and_rules():
    a = analyze_config('{"debug": true, "db": {"password": "p@ssw0rd", "host": "0.0.0.0"}}', filename="a.json")
    assert a.format == "json"
    keys = {s.key for s in a.settings}
    assert "db.password" in keys and "db.host" in keys
    assert "debug enabled" in _issues(a)
    assert "exposed credential" in _issues(a)


def test_properties_weak_cred_and_tls():
    a = analyze_config("server.ssl.verify=false\nspring.datasource.password=root\napp.debug=true",
                       filename="application.properties")
    issues = _issues(a)
    assert "TLS verification disabled" in issues
    assert "default/weak credential" in issues


def test_ini_and_xml():
    ini = analyze_config("[db]\npassword = secretpw\nverify_ssl = false", filename="cfg.ini")
    assert "exposed credential" in _issues(ini)
    xml = analyze_config('<configuration><appSettings><add key="ApiKey" value="AKIAIOSFODNN7EXAMPLE"/>'
                         '<add key="Debug" value="true"/></appSettings></configuration>', filename="web.config")
    assert xml.format == "xml"
    assert any(s.key == "ApiKey" for s in xml.settings)


def test_placeholder_values_not_flagged():
    a = analyze_config("API_KEY=your_api_key_here\nPASSWORD=changeme\nSECRET=", filename=".env")
    # 'changeme' is a known weak credential (flagged), but the placeholder and empty are handled.
    assert "exposed credential" not in _issues(a)


def test_no_crash_on_garbage():
    a = analyze_config(":::not really config:::\n\x00\x01binary", filename="weird.conf")
    assert a.error is None
    assert isinstance(a.setting_count, int)


@pytest.mark.asyncio
async def test_analyze_config_tool_with_content():
    res = await srv.analyze_config(content="DEBUG=true\nDB_PASS=hunter2secret", filename=".env")
    assert res["setting_count"] == 2
    assert any(f["issue"] == "debug enabled" for f in res["findings"])


@pytest.mark.asyncio
async def test_analyze_config_tool_requires_input():
    res = await srv.analyze_config()
    assert res["error"] == "invalid_input"


@pytest.mark.asyncio
async def test_analyze_config_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "analyze_config" in tools
