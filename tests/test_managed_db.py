"""Managed-DB / warehouse credential classifier — secrets.py + config_audit.py (E.3).

Positive + negative coverage hardened from a 10-agent adversarial verification pass
(current provider formats, domain-suffix confusion, doc placeholders).
"""

from moonmcp.recon import config_audit as ca
from moonmcp.recon import secrets as sec

# Fabricated samples, split at a `+` so no CONTIGUOUS token/DSN literal appears in the
# source (GitHub push-protection scans raw bytes); reassembled at runtime.
PSCALE_PW = "pscale_" + "pw_abcdEFGH1234567890ijklMNOP.qrstUVWX"       # 35-char body (>=32)
PSCALE_TKN = "pscale_" + "tkn_ABCdef0123456789ghiJKLmnopQRSTuvwx"      # 34-char body
NEON = "postgresql://neondb_owner:" + "npg_fakePw123" + "@ep-cool-block-123456.us-east-2.aws.neon.tech/neondb"
NEON_ASYNCPG = "postgresql+asyncpg://neondb_owner:" + "npg_fakePw9" + "@ep-wispy-cloud-12345678-pooler.eastus2.azure.neon.tech/neondb"
ATLAS = "mongodb+srv://appuser:" + "fakePw123" + "@cluster0.ab12cd.mongodb.net/prod?retryWrites=true"
ATLAS_GOV = "mongodb+srv://appuser:" + "fakePw123" + "@mycluster.abcde.mongodbgov.net/prod"
UPSTASH_NOPW = "rediss://:" + "fakeTok12345XyZ" + "@glad-crayfish-131416.upstash.io:6379"
REDISLABS = "rediss://default:" + "fakePw9" + "@redis-12345.c250.eu-central-1-1.ec2.cloud.redislabs.com:6380"
TURSO = "libsql://my-db-myorg.turso.io"
TURSO_WSS = "wss://my-db-myorg.aws-us-east-1.turso.io"
SNOWFLAKE = "xy12345.us-east-1.snowflakecomputing.com"
SNOWFLAKE_APP = "myservice-myorg-myaccount.snowflakecomputing.app"
DATABRICKS = "dbc-a1b2c3d4-e5f6.cloud.databricks.com"
ELASTIC = "https://abc123.es.us-east-1.aws.found.io:9243"
ELASTIC_SERVERLESS = "https://sample-project-c990cb.es.us-east-1.aws.elastic.cloud"
BIGQUERY = '{"type": "service_account", "project_id": "p", "private_key": "' + "-----BEGIN " + 'PRIVATE KEY-----\\nMIIfake..."}'
BIGQUERY_MULTILINE = '{\n  "type": "service_account",\n  "project_id": "p",\n  "private_key": "' + "-----BEGIN " + 'PRIVATE KEY-----\\n..."\n}'


# -- secrets.py self-contained tokens / DSNs ---------------------------------
def test_secrets_catches_managed_db_tokens():
    for sample, expect in [
        (PSCALE_PW, "PlanetScale Token"),
        (PSCALE_TKN, "PlanetScale Token"),
        (NEON, "Neon Postgres DSN"),
        (NEON_ASYNCPG, "Neon Postgres DSN"),          # driver-qualified scheme
        (ATLAS, "MongoDB Atlas SRV DSN"),
        (ATLAS_GOV, "MongoDB Atlas SRV DSN"),          # Atlas for Government
        (UPSTASH_NOPW, "Upstash Redis DSN"),           # passwordless userinfo
        (REDISLABS, "Redis Cloud DSN"),                # redislabs.com domain
        (TURSO, "Turso libSQL URL"),
        (TURSO_WSS, "Turso libSQL URL"),               # wss scheme
    ]:
        names = {h.type for h in sec.scan_text(f'X="{sample}"')}
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
                             "Upstash Redis DSN", "Redis Cloud DSN", "Turso libSQL URL"}), (benign, names)


def test_secrets_no_false_positive_on_domain_confusion():
    # A look-alike suffix must NOT be flagged as the provider (the trailing boundary).
    for evil in [
        "postgresql://alice:s3kritPw@ep-x.us-east-2.aws.neon.tech.attacker.com/db",
        "rediss://default:realPw@my-db.upstash.io.attacker.example.com/x",
        "libsql://mydb.turso.io.attacker.example.com",
    ]:
        names = {h.type for h in sec.scan_text(evil)}
        assert not (names & {"Neon Postgres DSN", "Upstash Redis DSN", "Turso libSQL URL"}), (evil, names)


def test_secrets_suppresses_doc_placeholders():
    for placeholder in [
        "postgresql://user:password@ep-cool-123456.us-east-2.aws.neon.tech/dbname",
        "mongodb+srv://<db_username>:<db_password>@cluster0.abcde.mongodb.net/",
        "rediss://default:YOUR_PASSWORD@your-endpoint.upstash.io:6379",
    ]:
        names = {h.type for h in sec.scan_text(placeholder)}
        assert not (names & {"Neon Postgres DSN", "MongoDB Atlas SRV DSN", "Upstash Redis DSN"}), (placeholder, names)


# -- config_audit classifier -------------------------------------------------
def test_classify_managed_db_positives():
    cases = {
        PSCALE_PW: "PlanetScale token", NEON: "Neon Postgres DSN",
        NEON_ASYNCPG: "Neon Postgres DSN", ATLAS: "MongoDB Atlas DSN",
        ATLAS_GOV: "MongoDB Atlas DSN", UPSTASH_NOPW: "Upstash Redis DSN",
        REDISLABS: "Redis Cloud DSN", TURSO: "Turso libSQL endpoint",
        TURSO_WSS: "Turso libSQL endpoint", SNOWFLAKE: "Snowflake account",
        SNOWFLAKE_APP: "Snowflake account", DATABRICKS: "Databricks workspace",
        ELASTIC: "Elastic Cloud endpoint", ELASTIC_SERVERLESS: "Elastic Cloud endpoint",
        BIGQUERY: "BigQuery service account", BIGQUERY_MULTILINE: "BigQuery service account",
    }
    for value, service in cases.items():
        res = ca.classify_managed_db(value)
        assert res is not None and res[0] == service, (value, res)
    assert ca.classify_managed_db(NEON)[2] == "critical"
    assert ca.classify_managed_db(SNOWFLAKE)[2] == "medium"
    assert ca.classify_managed_db(ELASTIC)[2] == "medium"   # downgraded: bare endpoint


def test_classify_managed_db_negatives():
    for benign in [
        "postgresql://user:pass@localhost:5432/db",
        "postgresql://u:p@mydb.abc.us-east-1.rds.amazonaws.com/app",
        "mongodb://user:pass@localhost:27017/db",
        "https://example.com/api",
        # domain-suffix confusion
        "postgresql://alice:s3kritPw@ep-x.us-east-2.aws.neon.tech.attacker.com/db",
        "login.snowflakecomputing.com.evil-phish.example.net",
        # doc placeholders
        "postgresql://user:password@ep-cool-123456.us-east-2.aws.neon.tech/db",
        "mongodb+srv://<db_username>:<db_password>@cluster0.abcde.mongodb.net/",
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
