"""Injection knowledge base — structured data.

Each entry: id, name, aliases, cwe, owasp, severity, summary, root_causes,
contexts, detection_payloads[{payload, technique, expected_indicator}],
signatures[{type: error|regex|behavioral, value, meaning, technology}],
by_technology[{technology, notes, payloads, signatures}], false_positives,
remediation, references.

This is the seed dataset; it is expanded from authoritative sources (OWASP WSTG,
PortSwigger, PayloadsAllTheThings, HackTricks, MITRE CWE).
"""

from __future__ import annotations

INJECTIONS: list[dict] = [
    {
        "id": "sqli",
        "name": "SQL Injection",
        "aliases": ["sql injection", "sqli"],
        "cwe": ["CWE-89"],
        "owasp": "A03:2021 Injection",
        "severity": "critical",
        "summary": "Untrusted input is concatenated into a SQL query, letting an attacker alter its logic.",
        "root_causes": [
            "String concatenation / interpolation of user input into SQL instead of parameterised queries",
            "Dynamic query building without an allowlist for identifiers (table/column names, ORDER BY)",
        ],
        "contexts": ["URL/query parameters", "POST body", "HTTP headers", "cookies", "JSON fields"],
        "detection_payloads": [
            {"payload": "'", "technique": "error-based", "expected_indicator": "a database syntax error in the response"},
            {"payload": "1 AND 1=1 -- -", "technique": "boolean-blind", "expected_indicator": "same page as baseline (true condition)"},
            {"payload": "1 AND 1=2 -- -", "technique": "boolean-blind", "expected_indicator": "different/empty page (false condition)"},
            {"payload": "1' AND SLEEP(5)-- -", "technique": "time-based", "expected_indicator": "response delayed ~5s (MySQL)"},
        ],
        "signatures": [
            {"type": "error", "value": "You have an error in your SQL syntax", "meaning": "MySQL/MariaDB syntax error", "technology": "MySQL"},
            {"type": "error", "value": "Unclosed quotation mark after the character string", "meaning": "MSSQL string error", "technology": "MSSQL"},
            {"type": "regex", "value": r"ORA-0[0-9]{4}", "meaning": "Oracle error code", "technology": "Oracle"},
            {"type": "regex", "value": r"PostgreSQL.*ERROR", "meaning": "PostgreSQL error", "technology": "PostgreSQL"},
            {"type": "error", "value": "SQLITE_ERROR", "meaning": "SQLite error", "technology": "SQLite"},
        ],
        "by_technology": [
            {"technology": "MySQL", "notes": "Time delay via SLEEP().", "payloads": ["' OR SLEEP(5)-- -"], "signatures": ["You have an error in your SQL syntax", "check the manual that corresponds to your MySQL server version"]},
            {"technology": "PostgreSQL", "notes": "Time delay via pg_sleep().", "payloads": ["'||pg_sleep(5)--"], "signatures": ["PostgreSQL.*ERROR", "unterminated quoted string"]},
            {"technology": "MSSQL", "notes": "Time delay via WAITFOR DELAY.", "payloads": ["'; WAITFOR DELAY '0:0:5'--"], "signatures": ["Unclosed quotation mark", "Incorrect syntax near"]},
            {"technology": "Oracle", "notes": "Time delay via dbms_pipe.receive_message.", "payloads": ["'||dbms_pipe.receive_message(('a'),5)"], "signatures": ["ORA-01756", "quoted string not properly terminated"]},
        ],
        "false_positives": ["WAFs returning generic errors", "Applications that echo the payload without executing it"],
        "remediation": ["Use parameterised queries / prepared statements", "Use an ORM safely", "Allowlist identifiers; least-privilege DB accounts"],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection",
                       "https://portswigger.net/web-security/sql-injection"],
    },
    {
        "id": "xss",
        "name": "Cross-Site Scripting",
        "aliases": ["xss", "cross site scripting"],
        "cwe": ["CWE-79"],
        "owasp": "A03:2021 Injection",
        "severity": "high",
        "summary": "Untrusted input is reflected into HTML/JS without contextual encoding, executing attacker script in the victim's browser.",
        "root_causes": [
            "Output not encoded for its HTML/JS/attribute/URL context",
            "Dangerous DOM sinks (innerHTML, document.write, eval) fed from attacker-controlled sources",
        ],
        "contexts": ["reflected parameters", "stored content", "DOM (location.hash/search)", "HTTP headers"],
        "detection_payloads": [
            {"payload": "moonmcp7913", "technique": "reflection", "expected_indicator": "the unique marker appears verbatim (un-encoded) in the response"},
            {"payload": "<moonmcp>", "technique": "reflection", "expected_indicator": "the tag appears un-encoded (HTML context breakout possible)"},
            {"payload": "\"'><moonmcp>", "technique": "reflection", "expected_indicator": "quotes/brackets reflected un-encoded (attribute breakout)"},
        ],
        "signatures": [
            {"type": "behavioral", "value": "injected unique marker reflected without HTML-encoding of < > \" '", "meaning": "reflection into an exploitable context", "technology": "generic"},
        ],
        "by_technology": [],
        "false_positives": ["Marker reflected inside an already-encoded/escaped context", "Reflected in a JSON/text response with correct content-type (not HTML)"],
        "remediation": ["Contextual output encoding", "Content-Security-Policy", "Avoid dangerous DOM sinks; use textContent"],
        "references": ["https://owasp.org/www-community/attacks/xss/",
                       "https://portswigger.net/web-security/cross-site-scripting"],
    },
    {
        "id": "ssti",
        "name": "Server-Side Template Injection",
        "aliases": ["ssti", "template injection"],
        "cwe": ["CWE-1336", "CWE-94"],
        "owasp": "A03:2021 Injection",
        "severity": "critical",
        "summary": "User input is embedded into a server-side template that is then evaluated, often leading to RCE.",
        "root_causes": ["Concatenating user input into a template string that the engine then evaluates"],
        "contexts": ["template-rendered parameters", "email/name fields rendered into templates"],
        "detection_payloads": [
            {"payload": "${{<%[%'\"}}%\\", "technique": "polyglot", "expected_indicator": "a template/engine error (engine present)"},
            {"payload": "{{7*7}}", "technique": "math-eval", "expected_indicator": "'49' rendered (Jinja2/Twig)"},
            {"payload": "{{7*'7'}}", "technique": "engine-fingerprint", "expected_indicator": "'7777777' → Jinja2/Python; '49' → Twig"},
            {"payload": "${7*7}", "technique": "math-eval", "expected_indicator": "'49' rendered (Freemarker/Velocity/EL)"},
            {"payload": "<%= 7*7 %>", "technique": "math-eval", "expected_indicator": "'49' rendered (ERB/Ruby)"},
        ],
        "signatures": [
            {"type": "behavioral", "value": "arithmetic payload is evaluated to its result (e.g. 7*7 → 49) in the response", "meaning": "template evaluation of user input", "technology": "generic"},
        ],
        "by_technology": [
            {"technology": "Jinja2 (Python)", "notes": "{{7*'7'}} → 7777777", "payloads": ["{{7*7}}", "{{config}}"], "signatures": ["jinja2.exceptions", "TemplateSyntaxError"]},
            {"technology": "Twig (PHP)", "notes": "{{7*'7'}} → 49", "payloads": ["{{7*7}}", "{{_self}}"], "signatures": ["Twig\\\\Error"]},
            {"technology": "Freemarker (Java)", "notes": "${7*7} → 49", "payloads": ["${7*7}", "<#assign x=1>"], "signatures": ["FreeMarker template error", "freemarker.core"]},
        ],
        "false_positives": ["Math reflected as literal text without evaluation", "Client-side templating (not server-side)"],
        "remediation": ["Do not pass user input as template source", "Sandbox the template engine; use logic-less templates"],
        "references": ["https://portswigger.net/web-security/server-side-template-injection",
                       "https://owasp.org/www-community/attacks/Server_Side_Template_Injection"],
    },
]
