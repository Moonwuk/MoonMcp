"""Configuration-file analyzer.

Recon frequently surfaces config files — an exposed ``.env``, a leaked
``web.config``, ``application.properties`` inside a decompiled JAR, a
``docker-compose.yml`` in an open directory.  This module parses them across the
common formats, enumerates **every setting** grouped by category so you can
understand the whole configuration at a glance, and flags the security-relevant
ones: exposed secrets, ``DEBUG=true``, disabled TLS verification, wildcard CORS,
default/weak credentials, bind-to-all, and credentials embedded in connection
strings.

Pure standard library (json / configparser / xml.etree / regex) with a minimal
YAML/dotenv/.properties/PHP reader, so it works with zero dependencies.
"""

from __future__ import annotations

import configparser
import json
import re
from dataclasses import dataclass, field
from xml.etree import ElementTree

# ---------------------------------------------------------------------------
# format detection + parsing
# ---------------------------------------------------------------------------

_GENERIC_KV_RE = re.compile(
    r"""^[ \t]*(?:export[ \t]+)?["']?([A-Za-z0-9_.\-\[\]]{1,80})["']?[ \t]*[:=][ \t]*(.*?)[ \t]*$""")
_PHP_DEFINE_RE = re.compile(r"""define\(\s*['"]([^'"]+)['"]\s*,\s*['"]?([^'")]*)['"]?\s*\)""")
_PHP_ARR_RE = re.compile(r"""['"]([A-Za-z0-9_.\-]+)['"]\s*=>\s*['"]?([^'",\n)]*)['"]?""")


def detect_format(content: str, filename: str | None = None) -> str:
    name = (filename or "").lower()
    if name.endswith((".json",)) or content.lstrip()[:1] in "{[":
        try:
            json.loads(content)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass
    if name.endswith((".xml", ".config")) or content.lstrip().startswith("<?xml") or content.lstrip().startswith("<"):
        if "<" in content and ">" in content:
            return "xml"
    if name.endswith((".php",)) or "define(" in content or "=>" in content and "<?php" in content:
        return "php"
    if name.endswith((".yml", ".yaml")):
        return "yaml"
    if name.endswith((".properties",)):
        return "properties"
    if name.endswith((".ini", ".cfg", ".conf")) or re.search(r"^\[[^\]]+\]\s*$", content, re.MULTILINE):
        return "ini"
    if name.endswith(".env") or ".env" in name or re.search(r"^[A-Z0-9_]+=", content, re.MULTILINE):
        return "dotenv"
    # YAML-ish (indented key: value with no '=')
    if re.search(r"^\s*[A-Za-z0-9_.\-]+:\s", content, re.MULTILINE) and "=" not in content[:200]:
        return "yaml"
    return "generic"


def _flatten(obj, prefix: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _flatten(v, f"{prefix}[{i}]")
    else:
        out.append((prefix, "" if obj is None else str(obj)))
    return out


def _parse_json(content: str) -> list[tuple[str, str]]:
    return _flatten(json.loads(content))


def _parse_ini(content: str) -> list[tuple[str, str]]:
    cp = configparser.ConfigParser(strict=False, interpolation=None, allow_no_value=True)
    try:
        cp.read_string(content)
    except configparser.Error:
        return _parse_generic(content)
    out = []
    for section in cp.sections():
        for k, v in cp.items(section):
            out.append((f"{section}.{k}" if section != "DEFAULT" else k, v or ""))
    return out or _parse_generic(content)


def _parse_dotenv(content: str) -> list[tuple[str, str]]:
    out = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _GENERIC_KV_RE.match(line)
        if m:
            val = m.group(2)
            if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
                val = val[1:-1]
            out.append((m.group(1), val))
    return out


def _parse_properties(content: str) -> list[tuple[str, str]]:
    out, buf = [], ""
    for raw in content.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith(("#", "!")):
            continue
        if line.endswith("\\"):
            buf += line[:-1]
            continue
        line = buf + line
        buf = ""
        m = re.match(r"\s*([^=:\s]+)\s*[:=]\s*(.*)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_xml(content: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return _parse_generic(content)

    def walk(el, path):
        tag = el.tag.split("}")[-1]
        cur = f"{path}.{tag}" if path else tag
        # ASP.NET style <add key="X" value="Y"/> and connectionStrings
        if tag in ("add",) and "key" in el.attrib and "value" in el.attrib:
            out.append((el.attrib["key"], el.attrib["value"]))
        if tag in ("add",) and "name" in el.attrib and "connectionString" in el.attrib:
            out.append((el.attrib["name"], el.attrib["connectionString"]))
        for ak, av in el.attrib.items():
            if ak not in ("key", "value", "name", "connectionString"):
                out.append((f"{cur}@{ak}", av))
        if el.text and el.text.strip():
            out.append((cur, el.text.strip()))
        for child in el:
            walk(child, cur)

    walk(root, "")
    return out


def _parse_php(content: str) -> list[tuple[str, str]]:
    out = [(m.group(1), m.group(2)) for m in _PHP_DEFINE_RE.finditer(content)]
    out += [(m.group(1), m.group(2)) for m in _PHP_ARR_RE.finditer(content)]
    return out or _parse_generic(content)


def _parse_yaml(content: str) -> list[tuple[str, str]]:
    # Prefer PyYAML if available; else a minimal indent-based reader.
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(content)
        if data is not None:
            return _flatten(data)
    except Exception:
        pass
    out: list[tuple[str, str]] = []
    stack: list[tuple[int, str]] = []
    for raw in content.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:]
        m = re.match(r"([^:]+):\s*(.*)", line)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = ".".join(p for _, p in stack)
        full = f"{path}.{key}" if path else key
        if val in ("", "|", ">"):
            stack.append((indent, key))
        else:
            if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
                val = val[1:-1]
            out.append((full, val))
    return out


def _parse_generic(content: str) -> list[tuple[str, str]]:
    out = []
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith(("#", "//", ";")):
            continue
        m = _GENERIC_KV_RE.match(line)
        if m and m.group(1):
            val = m.group(2).rstrip(";,")
            if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
                val = val[1:-1]
            out.append((m.group(1), val))
    return out


_PARSERS = {
    "json": _parse_json, "ini": _parse_ini, "dotenv": _parse_dotenv,
    "properties": _parse_properties, "xml": _parse_xml, "php": _parse_php,
    "yaml": _parse_yaml, "generic": _parse_generic,
}


# ---------------------------------------------------------------------------
# classification + security rules
# ---------------------------------------------------------------------------

_CATEGORIES: list[tuple[str, str]] = [
    ("database", r"\b(db|database|mysql|postgres|pg|mongo|redis|sql|dsn|jdbc|datasource|conn)\b"),
    ("secret", r"\b(secret|password|passwd|pwd|token|api[_-]?key|apikey|private[_-]?key|client[_-]?secret|jwt|oauth|credential|access[_-]?key)\b"),
    ("cloud", r"\b(aws|s3|azure|gcp|gcloud|bucket|cloud|do_|digitalocean)\b"),
    ("email", r"\b(smtp|mail|sendgrid|mailgun|ses|imap|pop3)\b"),
    ("network", r"\b(host|port|url|uri|endpoint|bind|listen|cors|origin|allow|proxy|domain)\b"),
    ("debug", r"\b(debug|verbose|trace|log[_-]?level|display[_-]?errors|env|environment)\b"),
    ("feature", r"\b(feature|flag|enable|disable|toggle)\b"),
    ("auth", r"\b(auth|login|session|cookie|csrf|saml|ldap|sso)\b"),
]

_TRUTHY = {"true", "1", "yes", "on", "enabled", "enable"}
_FALSY = {"false", "0", "no", "off", "disabled", "disable"}
_WEAK_CREDS = {"", "admin", "root", "password", "pass", "123456", "changeme",
               "secret", "test", "guest", "default", "toor", "12345678"}
_PLACEHOLDER = {"", "changeme", "your_", "example", "xxxx", "placeholder", "todo",
                "<", "null", "none", "undefined", "${", "{{"}
_SECRET_KEY_RE = re.compile(
    r"(?i)(pass(word|wd)?|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|token|jwt|credential|auth[_-]?key|encryption[_-]?key)")
_CONN_STR_RE = re.compile(r"(?i)(jdbc:|mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://|amqp://|sqlserver://)")
_CONN_CREDS_RE = re.compile(r"://[^/\s:@]+:[^/\s:@]+@")


@dataclass
class Setting:
    key: str
    value: str
    category: str
    sensitive: bool = False


@dataclass
class ConfigFinding:
    severity: str
    key: str
    issue: str
    detail: str


@dataclass
class ConfigAudit:
    format: str
    setting_count: int
    settings: list[Setting] = field(default_factory=list)
    findings: list[ConfigFinding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str | None = None


def _categorize(key: str) -> str:
    k = key.lower()
    for cat, pat in _CATEGORIES:
        if re.search(pat, k):
            return cat
    return "other"


def _redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 6:
        return "***"
    return f"{v[:3]}…{v[-2:]} ({len(v)} chars)"


def _looks_placeholder(v: str) -> bool:
    low = v.strip().lower()
    if low in _PLACEHOLDER:
        return True
    # A short generic token (null/none/todo/xxxx) must only match at the start — never
    # as an unanchored substring, or a real secret that merely CONTAINS it (e.g.
    # "aZnullQ2p9Kx8vT") would be wrongly suppressed. Substring match is reserved for
    # long, specific markers (changeme / placeholder / example / undefined).
    return any(low.startswith(p) or (len(p) >= 6 and p in low)
               for p in _PLACEHOLDER if len(p) > 2)


# Framework signing secrets: a leaked value here is not merely "a secret" — it is the
# key that lets an attacker FORGE a signed/encrypted blob the app trusts, turning a
# config leak into pre-auth RCE / auth bypass. Keyed by the key's basename (lowercased,
# after stripping any section/attribute prefix). Value = (framework, forge primitive,
# severity). Sourced from Synacktiv / GitGuardian / Vaadata / SySS research.
_SIGNING_SECRETS: dict[str, tuple[str, str, str]] = {
    "app_key": ("Laravel", "forge the encrypted laravel_session cookie → auto-unserialize() "
                "(when SESSION_DRIVER=cookie) → phpggc gadget RCE", "critical"),
    "encryptionkey": ("TYPO3", "forge __trustedProperties (HMAC-SHA1) → Extbase deserialization "
                      "/ arbitrary file read → RCE", "critical"),
    "app_secret": ("Symfony", "forge the /_fragment signed URI → internal render() → RCE", "critical"),
    "machinekey": ("ASP.NET", "forge __VIEWSTATE (ysoserial.net) → unauth RCE", "critical"),
    "validationkey": ("ASP.NET", "machineKey validationKey → forge a signed __VIEWSTATE blob", "critical"),
    "decryptionkey": ("ASP.NET", "machineKey decryptionKey → decrypt/forge an encrypted __VIEWSTATE", "critical"),
    "secret_key_base": ("Rails", "forge the session cookie → Marshal.load gadget → RCE", "critical"),
    "jwt_secret": ("JWT (HS*)", "sign arbitrary JWTs → forge any identity / escalate privilege", "critical"),
    "jwtsecret": ("JWT (HS*)", "sign arbitrary JWTs → forge any identity / escalate privilege", "critical"),
    "secret_key": ("Flask/Django", "sign/forge the session cookie → session tampering / auth bypass",
                   "high"),
}


def classify_signing_secret(key: str, value: str) -> tuple[str, str, str] | None:
    """If *key* names a known framework signing secret and *value* is a real key
    (not a placeholder), return ``(framework, forge_primitive, severity)`` — else None."""

    v = (value or "").strip()
    if not v or _looks_placeholder(v):
        return None
    parts = [p for p in re.split(r"[.\[\]@]", key.lower()) if p]
    base = parts[-1] if parts else key.lower()
    return _SIGNING_SECRETS.get(base)


# Managed / serverless database & warehouse credentials. A leaked DSN-with-creds or a
# provider token is a DIRECT path to the data — no exploit needed (the Snowflake UNC5537
# breach was entirely stolen creds + no MFA). Matched on the VALUE format (keys vary),
# ordered most-specific first. (service, value regex, severity, note). ``critical`` = the
# value itself grants access (embedded creds / a standalone token); ``high``/``medium`` =
# an endpoint that grants access once paired with a nearby password/token.
# Every host pattern carries a trailing ``(?![a-z0-9.\-])`` boundary so a look-alike
# suffix (e.g. ``neon.tech.attacker.com``) does NOT match. Formats verified against
# official docs + gitleaks rules (Neon +driver schemes, Atlas-for-Gov mongodbgov.net,
# passwordless Upstash, extra Redis Cloud domains, Snowflake .app, Elastic serverless).
_MANAGED_DB: list[tuple[str, re.Pattern[str], str, str]] = [
    ("BigQuery service account",
     re.compile(r'"type"\s*:\s*"service_account".{0,4000}?"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY',
                re.S), "critical",
     "GCP service-account JSON with a private key — direct BigQuery / GCP data access"),
    ("PlanetScale token",
     re.compile(r"(?i)\bpscale_(?:pw|tkn|oauth)_[\w=.\-]{32,64}(?![\w=.\-])"), "critical",
     "PlanetScale password / service token — direct MySQL access"),
    ("Neon Postgres DSN",
     re.compile(r"(?i)postgres(?:ql)?(?:\+[a-z0-9]+)?://[^\s:@/]+:[^\s:@/]+@ep-[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.neon\.tech(?![a-z0-9.\-])"),
     "critical", "Neon Postgres DSN with embedded credentials — direct DB read/write"),
    ("MongoDB Atlas DSN",
     re.compile(r"(?i)mongodb\+srv://[^\s:@/]+:[^\s:@/]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)+\.mongodb(?:gov)?\.net(?![a-z0-9.\-])"),
     "critical", "MongoDB Atlas SRV DSN with embedded credentials — direct DB read/write"),
    ("Upstash Redis DSN",
     re.compile(r"(?i)rediss?://[^\s:@/]*:[^\s:@/]+@[a-z0-9\-]+\.upstash\.io(?![a-z0-9.\-])"), "critical",
     "Upstash Redis DSN with embedded credentials — direct cache/DB access"),
    ("Redis Cloud DSN",
     re.compile(r"(?i)rediss?://[^\s:@/]*:[^\s:@/]+@[a-z0-9.\-]+\.(?:redis-cloud\.com|redislabs\.com|rlrcp\.com|db\.redis\.io)(?![a-z0-9.\-])"),
     "critical", "Redis Cloud DSN with embedded credentials — direct cache/DB access"),
    ("Turso libSQL endpoint",
     re.compile(r"(?i)(?:libsql|wss?|https?)://[a-z0-9][a-z0-9.\-]*\.turso\.io(?![a-z0-9.\-])"), "high",
     "Turso libSQL endpoint — with the TURSO_AUTH_TOKEN (a JWT) = full DB access"),
    ("Elastic Cloud endpoint",
     re.compile(r"(?i)https?://[a-z0-9\-]+\.(?:(?:es|kb|apm|ent|fleet)\.)?[a-z0-9\-.]+\.(?:found\.io|elastic-cloud\.com|cloud\.es\.io|elastic\.cloud|ip\.es\.io)(?![a-z0-9.\-])"),
     "medium", "Elastic Cloud endpoint — with ELASTIC_PASSWORD / an API key = cluster access"),
    ("Snowflake account",
     re.compile(r"(?i)(?<![a-z0-9._\-])[a-z0-9][a-z0-9_\-]*(?:\.[a-z0-9\-]+){0,3}\.snowflakecomputing\.(?:com|app)(?![a-z0-9.\-])"),
     "medium", "Snowflake account endpoint — with a leaked user/password or PAT = full warehouse "
     "access (the UNC5537 pattern)"),
    ("Databricks workspace",
     re.compile(r"(?i)\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.(?:cloud\.databricks\.com|azuredatabricks\.net|gcp\.databricks\.com)(?![a-z0-9.\-])"),
     "medium", "Databricks workspace — with a dapi… PAT = full workspace / SQL access"),
]

# Literal placeholder credentials used in provider docs (not real secrets).
_PLACEHOLDER_CRED = {"password", "pass", "changeme", "example", "demo", "test",
                     "secret", "user", "username", "dbpassword", "yourpassword"}
_DSN_PASS_RE = re.compile(r"://[^\s:/@]*:([^\s:/@]+)@")


def _placeholder_cred(value: str) -> bool:
    low = value.lower()
    if "<" in value or ">" in value:
        return True
    if any(t in low for t in ("your_", "your-", "example", "placeholder", "changeme", "xxxx", "dummy")):
        return True
    m = _DSN_PASS_RE.search(value)
    return bool(m and m.group(1).lower() in _PLACEHOLDER_CRED)


def classify_managed_db(value: str) -> tuple[str, str, str] | None:
    """If *value* is a managed-DB / warehouse DSN, token, or endpoint (not a doc
    placeholder), return ``(service, note, severity)`` — else None."""

    v = (value or "").strip()
    if not v or _looks_placeholder(v) or _placeholder_cred(v):
        return None
    for service, rx, severity, note in _MANAGED_DB:
        if rx.search(v):
            return (service, note, severity)
    return None


def _rule_checks(key: str, value: str) -> list[ConfigFinding]:
    k, v = key.lower(), (value or "").strip()
    vlow = v.lower()
    findings: list[ConfigFinding] = []

    # Exposed secret with a real value
    if _SECRET_KEY_RE.search(k) and v and not _looks_placeholder(v) and "verify" not in k and "enable" not in k:
        if vlow in _WEAK_CREDS:
            findings.append(ConfigFinding("high", key, "default/weak credential",
                                          f"credential-like setting uses a weak value ({v!r})"))
        else:
            findings.append(ConfigFinding("high", key, "exposed credential",
                                          "a secret/credential value is present in the config"))

    # Debug / non-prod env
    if re.search(r"\b(debug|display[_-]?errors|app[_-]?debug|whoops)\b", k) and vlow in _TRUTHY:
        findings.append(ConfigFinding("medium", key, "debug enabled",
                                      "debug/verbose errors enabled — leaks stack traces & internals"))
    if re.search(r"\b(env|environment)\b", k) and vlow in {"dev", "development", "local", "test", "staging", "debug"}:
        findings.append(ConfigFinding("low", key, "non-production environment",
                                      f"environment set to {v!r}"))

    # TLS/SSL verification disabled
    if re.search(r"(verify|reject[_-]?unauthorized|check[_-]?hostname|ssl[_-]?verify|tls[_-]?verify|verify[_-]?peer)", k):
        if vlow in _FALSY:
            findings.append(ConfigFinding("high", key, "TLS verification disabled",
                                          "certificate/host verification turned off — MITM exposure"))

    # Wildcard CORS / allowed hosts
    if re.search(r"(cors|allow.*origin|access.control.allow.origin|allowed[_-]?hosts?)", k) and ("*" in v):
        findings.append(ConfigFinding("medium", key, "wildcard CORS / allowed hosts",
                                      f"permissive wildcard value ({v!r})"))

    # Bind to all interfaces
    if "0.0.0.0" in v or vlow == "::":
        findings.append(ConfigFinding("low", key, "bound to all interfaces",
                                      "service listens on 0.0.0.0 — ensure it's not unintentionally exposed"))

    # Explicitly disabled security
    if re.search(r"(disable|skip|no)[_-]?(auth|security|csrf|ssl|tls|verify|check)", k) and vlow in _TRUTHY:
        findings.append(ConfigFinding("high", key, "security control disabled",
                                      f"{key} disables a protection"))
    if re.search(r"(insecure|dangerously|unsafe|allow[_-]?insecure)", k) and vlow in _TRUTHY:
        findings.append(ConfigFinding("medium", key, "insecure option enabled", f"{key} = {v!r}"))

    # Cookie flags off
    if re.search(r"cookie.*secure|session.*secure|secure.*cookie", k) and vlow in _FALSY:
        findings.append(ConfigFinding("medium", key, "insecure cookie",
                                      "Secure flag disabled — cookies sent over HTTP"))
    if re.search(r"cookie.*httponly|httponly", k) and vlow in _FALSY:
        findings.append(ConfigFinding("low", key, "cookie without HttpOnly",
                                      "cookie readable from JavaScript"))

    # Credentials in a connection string
    if _CONN_STR_RE.search(v) and _CONN_CREDS_RE.search(v):
        findings.append(ConfigFinding("high", key, "credentials in connection string",
                                      "connection string embeds username:password"))

    return findings


def analyze_config(content: str, filename: str | None = None) -> ConfigAudit:
    fmt = detect_format(content, filename)
    try:
        pairs = _PARSERS[fmt](content)
        if not pairs and fmt != "generic":
            pairs = _parse_generic(content)
            if pairs:
                fmt += "→generic"
    except Exception as exc:  # never let a parser crash the tool
        pairs = _parse_generic(content)
        fmt = f"{fmt}(fallback: {type(exc).__name__})"

    audit = ConfigAudit(format=fmt, setting_count=len(pairs))
    findings: list[ConfigFinding] = []
    forge_chains: list[dict] = []
    managed_db: list[dict] = []
    for key, value in pairs:
        cat = _categorize(key)
        rule_hits = _rule_checks(key, value)
        # A framework signing secret isn't just an exposed credential — it's a
        # forge-to-RCE / auth-bypass primitive. Flag it explicitly (and it catches
        # APP_KEY / machineKey, which the generic secret rule misses entirely).
        forge = classify_signing_secret(key, value)
        if forge is not None:
            framework, primitive, severity = forge
            rule_hits.append(ConfigFinding(
                severity, key, "forge-capable signing secret",
                f"{framework}: {primitive}"))
            forge_chains.append({"key": key, "framework": framework,
                                 "primitive": primitive, "severity": severity})
        # A managed-DB / warehouse DSN, token, or endpoint is a DIRECT path to the data
        # (no exploit) — classify it explicitly so it isn't lost among generic secrets.
        mdb = classify_managed_db(value)
        if mdb is not None:
            service, note, severity = mdb
            rule_hits.append(ConfigFinding(severity, key, "managed database credential", f"{service}: {note}"))
            managed_db.append({"key": key, "service": service, "note": note, "severity": severity})
        sensitive = cat == "secret" or forge is not None or mdb is not None or any(
            f.issue in ("exposed credential", "credentials in connection string") for f in rule_hits)
        shown = _redact(value) if sensitive and value else value
        audit.settings.append(Setting(key=key, value=shown[:200], category=cat, sensitive=sensitive))
        findings.extend(rule_hits)

    audit.findings = sorted(
        findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity, 5))
    by_sev: dict[str, int] = {}
    for f in audit.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    by_cat: dict[str, int] = {}
    for s in audit.settings:
        by_cat[s.category] = by_cat.get(s.category, 0) + 1
    audit.summary = {"by_severity": by_sev, "by_category": by_cat,
                     "sensitive_settings": sum(1 for s in audit.settings if s.sensitive),
                     "forge_chains": forge_chains, "managed_db": managed_db}
    return audit
