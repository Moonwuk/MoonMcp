"""Tests for the configuration-file analyzer."""

import pytest

from moonmcp import server as srv
from moonmcp.recon.config_audit import (
    analyze_config,
    classify_ingress_annotation,
    classify_signing_secret,
    detect_format,
)


def _issues(audit):
    return {f.issue for f in audit.findings}


def test_classify_ingress_annotation():
    hit = classify_ingress_annotation("nginx.ingress.kubernetes.io/configuration-snippet")
    assert hit is not None and hit[1] == "high"
    assert classify_ingress_annotation("nginx.ingress.kubernetes.io/auth-url")[1] == "medium"
    assert classify_ingress_annotation("nginx.ingress.kubernetes.io/ssl-passthrough")[1] == "low"
    # not an ingress annotation namespace → ignored (no false positive)
    assert classify_ingress_annotation("some.random/configuration-snippet") is None
    assert classify_ingress_annotation("spring.datasource.url") is None


def test_analyze_config_flags_ingress_annotation():
    manifest = (
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  annotations:\n"
        '    nginx.ingress.kubernetes.io/configuration-snippet: "more_set_headers x;"\n'
        '    nginx.ingress.kubernetes.io/auth-url: "http://auth.internal/check"\n'
    )
    audit = analyze_config(manifest, "ingress.yaml")
    annos = {r["annotation"] for r in audit.summary["ingress_risks"]}
    assert "configuration-snippet" in annos
    assert "auth-url" in annos
    assert "risky ingress annotation" in _issues(audit)


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


# -- framework signing-secret → forge-chain classifier -----------------------
def test_classify_signing_secret_maps_known_keys():
    assert classify_signing_secret("APP_KEY", "base64:c2VjcmV0a2V5c2VjcmV0a2V5c2VjcmV0MDA=")[0] == "Laravel"
    assert classify_signing_secret("system.web.machineKey@validationKey", "A1B2C3D4E5F6")[0] == "ASP.NET"
    assert classify_signing_secret("secret_key_base", "0a1b2c3d4e5f6a7b8c9d")[0] == "Rails"
    assert classify_signing_secret("APP_SECRET", "1f2e3d4c5b6a7988")[0] == "Symfony"


def test_classify_signing_secret_ignores_placeholders_and_unknowns():
    assert classify_signing_secret("APP_KEY", "") is None
    assert classify_signing_secret("APP_KEY", "changeme") is None       # placeholder
    assert classify_signing_secret("DB_PASSWORD", "hunter2secret") is None  # not a signing key
    assert classify_signing_secret("client_secret_key", "abcd1234") is None  # basename ≠ secret_key


def test_analyze_config_surfaces_laravel_forge_chain():
    # A real Laravel APP_KEY — the generic secret rule misses it (no "key" alt);
    # the classifier must flag it critical with a forge chain.
    env = "APP_ENV=production\nAPP_KEY=base64:aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsbzEyMw==\nSESSION_DRIVER=cookie\n"
    a = analyze_config(env, filename=".env")
    assert "forge-capable signing secret" in _issues(a)
    chains = a.summary["forge_chains"]
    assert len(chains) == 1 and chains[0]["framework"] == "Laravel"
    assert chains[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_analyze_config_tool_reports_forge_chains():
    res = await srv.analyze_config(
        content="<configuration><system.web><machineKey validationKey='0123456789ABCDEF0123456789ABCDEF' "
                "decryptionKey='FEDCBA98765432100123' /></system.web></configuration>",
        filename="web.config")
    chains = res["summary"]["forge_chains"]
    assert any(c["framework"] == "ASP.NET" for c in chains)


def test_bind_all_not_flagged_inside_private_cidr():
    a = analyze_config("allowlist=10.0.0.0/8\nrange=192.168.0.0/16", filename="a.env")
    assert "bound to all interfaces" not in _issues(a)     # CIDR is not a bind-all
    b = analyze_config("host=0.0.0.0", filename="b.env")
    assert "bound to all interfaces" in _issues(b)         # a genuine bind-all still flags
