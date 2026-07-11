"""Managed-DB / warehouse credential classifier — secrets.py + config_audit.py (E.3)."""

from moonmcp.recon import config_audit as ca
from moonmcp.recon import secrets as sec

# Fabricated samples per provider, split at a `+` so no CONTIGUOUS token/DSN literal
# appears in the source (GitHub push-protection scans raw bytes); each is reassembled
# at runtime, and the detectors match the reassembled string.
PSCALE_PW = "pscale_" + "pw_abcdEFGH1234567890ijklMNOP.qrstUVWX"
PSCALE_TKN = "pscale_" + "tkn_ABCdef0123456789ghiJKLmnopQRSTuvwx"
NEON = "postgresql://neondb_owner:" + "npg_fakePw123" + "@ep-cool-block-123456.us-east-2.aws.neon.tech/neondb"
ATLAS = "mongodb+srv://appuser:" + "fakePw123" + "@cluster0.ab12cd.mongodb.net/prod?retryWrites=true"
UPSTASH = "rediss://default:" + "fakeTok12345XyZ" + "@us1-cool-cat-12345.upstash.io:6379"
REDIS_CLOUD = "redis://default:" + "fakePw0rd" + "@redis-12345.c1.us-east-1-2.ec2.redis-cloud.com:12345"
TURSO = "libsql://my-db-myorg.turso.io"
SNOWFLAKE = "xy12345.us-east-1.snowflakecomputing.com"
DATABRICKS = "dbc-a1b2c3d4-e5f6.cloud.databricks.com"
ELASTIC = "https://abc123.es.us-east-1.aws.found.io:9243"
BIGQUERY = '{"type": "service_account", "project_id": "p", "private_key": "' + "-----BEGIN " + 'PRIVATE KEY-----\\nMIIfake..."}'


# -- secrets.py self-contained tokens / DSNs ---------------------------------
def test_secrets_catches_managed_db_tokens():
    for sample, expect in [
        (PSCALE_PW, "PlanetScale Password"),
        (PSCALE_TKN, "PlanetScale Service Token"),
        (NEON, "Neon Postgres DSN"),
        (ATLAS, "MongoDB Atlas SRV DSN"),
        (UPSTASH, "Upstash/Redis-Cloud DSN"),
        (REDIS_CLOUD, "Upstash/Redis-Cloud DSN"),
        (TURSO, "Turso libSQL URL"),
    ]:
        names = {h.type for h in sec.scan_text(f'DATABASE_URL="{sample}"')}
        assert expect in names, (expect, names)


def test_secrets_redacts_dsn_password():
    hit = next(h for h in sec.scan_text(NEON) if h.type == "Neon Postgres DSN")
    assert "npg_fakePw123" not in hit.redacted


def test_secrets_no_false_positive_on_plain_dsns():
    for benign in [
        "postgresql://user:pass@localhost:5432/db",
        "postgresql://u:p@mydb.abc.us-east-1.rds.amazonaws.com:5432/app",
        "mongodb://user:pass@localhost:27017/db",
        "redis://localhost:6379/0",
    ]:
        names = {h.type for h in sec.scan_text(benign)}
        assert not (names & {"Neon Postgres DSN", "MongoDB Atlas SRV DSN",
                             "Upstash/Redis-Cloud DSN", "Turso libSQL URL"}), (benign, names)


# -- config_audit classifier -------------------------------------------------
def test_classify_managed_db_positives():
    cases = {
        PSCALE_PW: "PlanetScale token", NEON: "Neon Postgres DSN",
        ATLAS: "MongoDB Atlas DSN", UPSTASH: "Upstash Redis DSN",
        REDIS_CLOUD: "Redis Cloud DSN", TURSO: "Turso libSQL endpoint",
        SNOWFLAKE: "Snowflake account", DATABRICKS: "Databricks workspace",
        ELASTIC: "Elastic Cloud endpoint", BIGQUERY: "BigQuery service account",
    }
    for value, service in cases.items():
        res = ca.classify_managed_db(value)
        assert res is not None and res[0] == service, (value, res)
    # critical = value grants access directly
    assert ca.classify_managed_db(NEON)[2] == "critical"
    assert ca.classify_managed_db(SNOWFLAKE)[2] == "medium"


def test_classify_managed_db_negatives():
    for benign in [
        "postgresql://user:pass@localhost:5432/db",
        "postgresql://u:p@mydb.abc.us-east-1.rds.amazonaws.com/app",
        "mongodb://user:pass@localhost:27017/db",
        "https://example.com/api",
        "changeme",
        "",
    ]:
        assert ca.classify_managed_db(benign) is None, benign


def test_analyze_config_surfaces_managed_db():
    env = "\n".join([
        f'DATABASE_URL="{NEON}"',
        f"SNOWFLAKE_ACCOUNT={SNOWFLAKE}",
        "APP_ENV=production",
    ])
    audit = ca.analyze_config(env, filename=".env")
    services = {m["service"] for m in audit.summary["managed_db"]}
    assert {"Neon Postgres DSN", "Snowflake account"} <= services
    assert any(f.issue == "managed database credential" and f.severity == "critical"
               for f in audit.findings)
