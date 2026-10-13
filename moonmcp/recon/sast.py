"""Static Application Security Testing (SAST) — lightweight code-level scanner.

A regex + pattern-based static analyser that inspects source files for common
vulnerability classes:

* **SQL injection** — string concatenation or f-strings feeding into
  ``execute()``, ``query()``, ``cursor.execute()``.
* **XSS** — ``innerHTML``, ``document.write()``, ``dangerouslySetInnerHTML``,
  ``eval()`` of user-controlled input.
* **Hardcoded secrets** — AWS/GCP/GitHub tokens, DB connection strings,
  generic password/secret assignments.  Reuses the high-precision pattern
  set from ``recon.secrets`` (gitleaks-derived) plus DB-connection-string
  patterns.
* **SSRF** — HTTP fetch calls (``requests.get``, ``fetch()``, ``urlopen``)
  with a variable argument (candidate for user-controlled URL).
* **Path traversal** — ``open()`` / ``read_file()`` / ``fs.readFile()`` with
  ``../`` sequences or request parameters.
* **Insecure deserialization** — ``pickle.loads``, ``yaml.load`` (unsafe),
  ``unserialize()``, ``readObject()``.

The scanner is deliberately conservative: it works on a single file or a
directory tree, uses regex heuristics (not AST parsing) for cross-language
support, and returns *leads* — each finding includes the file, line number,
rule name, severity and a code snippet for manual triage.

No network access is required; this is a purely local analysis tool.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

# Reuse the curated secret patterns from the secrets module for consistency.
from .secrets import scan_text as _scan_secrets, SecretHit


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SASTFinding:
    """A single static-analysis finding."""
    file: str
    line: int
    rule: str
    severity: str  # critical | high | medium | low | info
    snippet: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "snippet": self.snippet,
            "detail": self.detail,
        }


@dataclass
class SASTScanResult:
    """Aggregate result of scanning one or more files."""
    findings: list[SASTFinding] = field(default_factory=list)
    files_scanned: int = 0
    language: str = "auto"
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.findings)

    def summary(self) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
        return {
            "files_scanned": self.files_scanned,
            "total_findings": self.count,
            "by_severity": by_severity,
            "by_rule": by_rule,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "language": self.language,
            "errors": self.errors,
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_EXT_MAP: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".php": "php",
    ".java": "java", ".jsp": "java",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".tsx": "javascript",
    ".ts": "typescript",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".h": "c", ".hpp": "cpp",
}

# File extensions we scan by default.
_SCAN_EXTENSIONS = set(_EXT_MAP.keys()) | {".html", ".htm", ".vue", ".svelte"}


def _detect_language(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    return _EXT_MAP.get(ext, "unknown")


def _detect_language_from_content(text: str) -> str:
    heuristics = [
        (r"^\s*#!/usr/bin/env python", "python"),
        (r"^\s*#!/usr/bin/python", "python"),
        (r"^\s*<\?php", "php"),
    ]
    for pat, lang in heuristics:
        if re.search(pat, text, re.MULTILINE):
            return lang
    return "unknown"


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# Each rule: (rule_name, severity, list of compiled regex patterns, languages)
# A rule fires if ANY pattern matches.  Patterns operate on a single line.

def _compile(rules: list[tuple[str, str, tuple[str, ...] | list[str], tuple[str, ...] | str]]) -> list[tuple[str, str, list[re.Pattern[str]], tuple[str, ...]]]:
    result: list[tuple[str, str, list[re.Pattern[str]], tuple[str, ...]]] = []
    for name, sev, pats, langs in rules:
        compiled = [re.compile(p, re.IGNORECASE) for p in pats]
        lang_tuple: tuple[str, ...] = (langs,) if isinstance(langs, str) else tuple(langs)
        result.append((name, sev, compiled, lang_tuple))
    return result


# --- SQL Injection rules ---
_Sqli_RULES = _compile([
    (
        "sqli-string-concat-execute",
        "high",
        [
            # Python: cursor.execute("SELECT ... " + var) or f"SELECT ...{var}"
            r"""execute\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?['"]\s*\+""",
            r"""execute\s*\(\s*f['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?\{""",
            r"""\.(?:execute|executemany)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*%""",
            r"""\.(?:execute|executemany)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\.format""",
            # PHP: mysqli_query($conn, "SELECT ... " . $var)
            r"""mysqli_query\s*\([^,]+,\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\.""",
            r"""mysql_query\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\.""",
            # Java: stmt.executeQuery("SELECT ... " + var)
            r"""executeQuery\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\+""",
            r"""executeUpdate\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\+""",
            # JS: connection.query("SELECT ... " + var)
            r"""\bquery\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\+""",
            r"""\bquery\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE)\b.*?\$\{""",
            # C#: SqlCommand("SELECT ... " + var)
            r"""SqlCommand\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\+""",
        ],
        ("python", "php", "java", "javascript", "typescript", "csharp"),
    ),
    (
        "sqli-fstring-execute",
        "high",
        [
            # Python f-string in execute: execute(f"SELECT ... {var}")
            r"""execute\s*\(\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*\{""",
            r"""\.(?:execute|executemany)\s*\(\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*\{""",
        ],
        ("python",),
    ),
    (
        "sqli-string-concat-query-var",
        "high",
        [
            # SQL query assigned to a variable with string concatenation
            # Python: query = "SELECT ... " + var
            r"""(?:query|sql|stmt|statement|q)\s*=\s*['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?['"]\s*\+""",
            # Python: query = f"SELECT ... {var}"
            r"""(?:query|sql|stmt|statement|q)\s*=\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*\{""",
            # Python: query = "SELECT ... %s" % var
            r"""(?:query|sql|stmt|statement|q)\s*=\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*%""",
            # Python: query = "SELECT ... {}".format(var)
            r"""(?:query|sql|stmt|statement|q)\s*=\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\.format""",
            # PHP: $sql = "SELECT ... " . $var
            r"""\$(?:sql|query|stmt|statement)\s*=\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\.""",
            # Java: String sql = "SELECT ... " + var
            r"""String\s+(?:sql|query|stmt)\s*=\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\+""",
            # JS: const query = "SELECT ... " + var
            r"""(?:const|let|var)\s+(?:sql|query|stmt)\s*=\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"]\s*\+""",
            r"""(?:const|let|var)\s+(?:sql|query|stmt)\s*=\s*`(?:SELECT|INSERT|UPDATE|DELETE)\b.*?\$\{""",
        ],
        ("python", "php", "java", "javascript", "typescript"),
    ),
])

# --- XSS rules ---
_XSS_RULES = _compile([
    (
        "xss-innerhtml",
        "medium",
        [
            r"""\.innerHTML\s*=\s*(?!['"](?:\s*|\)\s*;?\s*$))""",  # innerHTML = non-static
            r"""\.innerHTML\s*\+=\s*""",
        ],
        ("javascript", "typescript"),
    ),
    (
        "xss-document-write",
        "medium",
        [
            r"""document\.write\s*\(""",
            r"""document\.writeln\s*\(""",
        ],
        ("javascript", "typescript"),
    ),
    (
        "xss-dangerouslysetinnerhtml",
        "high",
        [
            r"""dangerouslySetInnerHTML""",
            r"""dangerouslySetInnerHtml""",
        ],
        ("javascript", "typescript"),
    ),
    (
        "xss-eval-userinput",
        "high",
        [
            r"""\beval\s*\(\s*(?:request|req|params|query|body|input|data|args)\b""",
            r"""\beval\s*\(\s*(?:document\.|window\.|location\.)""",
            r"""\beval\s*\([^)]*\b(?:request|req|params|query|body|input|data|args)\.""",  # eval(JSON.parse(req.body...))
        ],
        ("javascript", "typescript", "python"),
    ),
    (
        "xss-echo-request",
        "high",
        [
            # PHP: echo $_GET['x'] / echo $_POST['x'] / echo $_REQUEST['x'] without htmlspecialchars
            r"""echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\b""",
            r"""print\s+\$_(?:GET|POST|REQUEST|COOKIE)\b""",
            r"""printf\s*\(\s*['"][^'"]*['"]\s*,\s*\$_(?:GET|POST|REQUEST)\b""",
        ],
        ("php",),
    ),
])

# --- SSRF rules ---
_SSRF_RULES = _compile([
    (
        "ssrf-fetch-userinput",
        "medium",
        [
            # Python: requests.get(var) / urllib.request.urlopen(var)
            r"""\brequests\.(?:get|post|put|delete|head|patch|request)\s*\(\s*(?:request\.|req\.|input|params|data|args|url_var|user_url|target_url)""",
            r"""\burllib\.request\.urlopen\s*\(\s*(?:request\.|req\.|input|params|data|args)""",
            # JS: fetch(var) / axios.get(var)
            r"""\bfetch\s*\(\s*(?:request\.|req\.|params|body|input|data|args)\b""",
            r"""\baxios\.(?:get|post|put|delete|request)\s*\(\s*(?:request\.|req\.|params|body|input|data|args)\b""",
            # PHP: file_get_contents($_GET['url'])
            r"""file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)""",
            r"""curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)""",
            # Java: URL(var).openConnection()
            r"""new\s+URL\s*\(\s*(?:request\.|req\.|input|params|getParameter)""",
        ],
        ("python", "javascript", "typescript", "php", "java"),
    ),
])

# --- Path traversal rules ---
_PATH_TRAVERSAL_RULES = _compile([
    (
        "path-traversal-open",
        "medium",
        [
            # Python: open("../" + var) / open(f".../{request...}")
            r"""\bopen\s*\(\s*(?:f['"]|['"])?(?:\.\./|%\.\./|.*\.\..*['"]\s*\+)""",
            r"""\bopen\s*\(\s*f['"][^'"]*\.\./""",
            r"""\bopen\s*\(\s*['"][^'"]*['"]\s*\+\s*(?:request\.|req\.|input|params|args|data)""",
            # JS: fs.readFile("../" + req.params)
            r"""fs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:\.\./|.*\.\./|['"][^'"]*['"]\s*\+\s*(?:req|request|params))""",
            r"""readFile\s*\(\s*(?:\.\./|.*\.\./|['"][^'"]*['"]\s*\+\s*(?:req|request|params))""",
            # PHP: file_get_contents("../" . $_GET['file'])
            r"""file_get_contents\s*\(\s*(?:\.\./|.*\.\./|['"][^'"]*['"]\s*\.\s*\$_(?:GET|POST|REQUEST))""",
            r"""fopen\s*\(\s*(?:\.\./|.*\.\./|['"][^'"]*['"]\s*\.\s*\$_(?:GET|POST|REQUEST))""",
            # Java: new File("../" + request.getParameter)
            r"""new\s+File\s*\(\s*(?:\.\./|.*\.\./|['"][^'"]*['"]\s*\+\s*(?:request|req|getParameter))""",
        ],
        ("python", "javascript", "typescript", "php", "java"),
    ),
])

# --- Insecure deserialization rules ---
_DESERIALIZE_RULES = _compile([
    (
        "deserialization-pickle",
        "high",
        [
            r"""\bpickle\.loads?\s*\(""",
            r"""\bcPickle\.loads?\s*\(""",
            r"""\b_pickle\.Unpickler\s*\(""",
            r"""\bdill\.loads?\s*\(""",
        ],
        ("python",),
    ),
    (
        "deserialization-yaml-unsafe",
        "high",
        [
            # yaml.load() without Loader= or using yaml.unsafe_load
            r"""\byaml\.load\s*\((?!.*Loader\s*=)""",
            r"""\byaml\.unsafe_load\s*\(""",
            r"""\byaml\.full_load\s*\(""",
        ],
        ("python",),
    ),
    (
        "deserialization-php",
        "high",
        [
            r"""\bunserialize\s*\(""",
        ],
        ("php",),
    ),
    (
        "deserialization-java",
        "high",
        [
            r"""\bObjectInputStream\b""",
            r"""\.readObject\s*\(""",
            r"""\bXMLDecoder\b""",
            r"""\bSerializationUtils\.deserialize\b""",
        ],
        ("java",),
    ),
    (
        "deserialization-js",
        "medium",
        [
            r"""\beval\s*\(\s*\(?[^)]*\bJSON\.parse\b""",
        ],
        ("javascript", "typescript"),
    ),
])

# --- Hardcoded password / credential rules ---
_HARDCODED_CRED_RULES = _compile([
    (
        "hardcoded-password",
        "high",
        [
            # Python/JS/PHP/Java: password = "literal"
            r"""(?:password|passwd|pwd)\s*[:=]\s*['"](?!\$\{|\$\w|\{\{)(?:[^'"]{3,})['"]""",
            # PHP: $password = "literal"
            r"""\$(?:password|passwd|pwd)\s*=\s*['"](?:[^'"]{3,})['"]""",
            # C#: string password = "literal"
            r"""string\s+(?:password|passwd|pwd)\s*=\s*['"](?:[^'"]{3,})['"]""",
            # Java: String password = "literal"
            r"""String\s+(?:password|passwd|pwd)\s*=\s*['"](?:[^'"]{3,})['"]""",
            # DB connection string with password
            r"""(?:mongodb|postgres|mysql|redis|amqp)://[^:\s]+:[^@\s]+@""",
            r"""Data\s+Source=[^;]+;[^;]*Password\s*=\s*[^;]+""",
        ],
        ("python", "javascript", "typescript", "php", "java", "csharp", "go", "ruby"),
    ),
    (
        "hardcoded-api-key",
        "high",
        [
            r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"](?:[A-Za-z0-9_\-]{16,})['"]""",
            r"""(?:secret[_-]?key|secretkey)\s*[:=]\s*['"](?:[A-Za-z0-9_\-]{16,})['"]""",
            r"""(?:auth[_-]?token|access[_-]?token)\s*[:=]\s*['"](?:[A-Za-z0-9_\-]{16,})['"]""",
        ],
        ("python", "javascript", "typescript", "php", "java", "csharp", "go", "ruby"),
    ),
])

# Placeholder password values that should NOT be flagged
_CRED_PLACEHOLDERS = {
    "", "xxx", "placeholder", "changeme", "your_password", "yourpassword",
    "example", "test", "demo", "secret", "password", "pass", "none",
    "null", "undefined", "todo", "fixme", "your_api_key", "yourapikey",
    "your-secret-key", "your_api_key_here", "os.environ",
    "os.getenv", "config.get", "getenv", "environ",
    "process.env", "${", "$_ENV", "settings.",
}

_DSN_PASS_RE = re.compile(r"://[^:\s/@]+:([^:\s/@]+)@")


def _is_placeholder_credential(value: str) -> bool:
    """Check if a credential value is a placeholder rather than a real secret."""
    low = value.lower().strip("'\"")
    if low in _CRED_PLACEHOLDERS:
        return True
    if any(p in low for p in ("example", "changeme", "your_", "your-",
                              "placeholder", "xxxx", "todo", "fixme",
                              "os.environ", "os.getenv", "process.env",
                              "config.get", "settings.", "getenv")):
        return True
    # DSN with literal user:password@
    m = _DSN_PASS_RE.search(value)
    if m and m.group(1).lower() in {"password", "pass", "secret",
                                    "changeme", "user", "username"}:
        return True
    return False


def _extract_credential_value(line: str) -> str | None:
    """Extract the credential value from a password = "..." line."""
    m = re.search(r"""[:=]\s*['"]([^'"]*)['"]""", line)
    if m:
        return m.group(1)
    return None


# All rule groups, keyed by vulnerability class
_ALL_RULE_GROUPS: list[tuple[str, list[tuple[str, str, list[re.Pattern], tuple[str, ...]]]]] = [
    ("sqli", _Sqli_RULES),
    ("xss", _XSS_RULES),
    ("ssrf", _SSRF_RULES),
    ("path_traversal", _PATH_TRAVERSAL_RULES),
    ("deserialization", _DESERIALIZE_RULES),
    ("hardcoded_credentials", _HARDCODED_CRED_RULES),
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB per file
_MAX_LINE_SNIPPET = 120


class SASTScanner:
    """Static code analyser — scans files for vulnerability patterns.

    Usage::

        scanner = SASTScanner()
        result = scanner.scan("/path/to/code", language="auto")
        for finding in result.findings:
            print(f"{finding.file}:{finding.line} [{finding.rule}] {finding.severity}")
    """

    def __init__(self) -> None:
        self._rule_groups = _ALL_RULE_GROUPS

    def scan(self, path: str, language: str = "auto") -> SASTScanResult:
        """Scan a file or directory for vulnerability patterns.

        Args:
            path: Path to a file or directory to scan.
            language: Language hint (auto|python|php|java|javascript|
                typescript|csharp|go|ruby|c|cpp).  When ``auto``, language is
                detected per-file from the extension.

        Returns:
            SASTScanResult with findings, file count, and summary.
        """
        result = SASTScanResult(language=language)

        if os.path.isfile(path):
            files = [path]
        elif os.path.isdir(path):
            files = self._collect_files(path)
        else:
            result.errors[path] = "path not found"
            return result

        for filepath in files:
            try:
                self._scan_file(filepath, language, result)
                result.files_scanned += 1
            except Exception as exc:
                result.errors[filepath] = str(exc)

        return result

    def _collect_files(self, root: str) -> list[str]:
        """Recursively collect scannable source files from a directory."""
        files: list[str] = []
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                     "vendor", "dist", "build", ".idea", ".vscode", "target",
                     "bin", "obj"}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fname in sorted(filenames):
                ext = os.path.splitext(fname)[1].lower()
                if ext in _SCAN_EXTENSIONS:
                    files.append(os.path.join(dirpath, fname))
        return files

    def _scan_file(self, filepath: str, lang_hint: str, result: SASTScanResult) -> None:
        """Scan a single file for all rule groups."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as exc:
            result.errors[filepath] = str(exc)
            return

        if len(content) > _MAX_FILE_SIZE:
            result.errors[filepath] = f"file too large ({len(content)} bytes, max {_MAX_FILE_SIZE})"
            return

        # Determine language for this file
        if lang_hint and lang_hint != "auto":
            file_lang = lang_hint
        else:
            file_lang = _detect_language(filepath)
            if file_lang == "unknown":
                file_lang = _detect_language_from_content(content)

        lines = content.splitlines()

        # --- Pattern-based rules ---
        for _vuln_class, rule_group in self._rule_groups:
            for rule_name, severity, patterns, rule_langs in rule_group:
                # Skip rules that don't apply to this language
                if file_lang not in ("unknown", *rule_langs):
                    # If file_lang is unknown, apply all rules (catch-all)
                    if file_lang != "unknown":
                        continue
                for line_no, line in enumerate(lines, 1):
                    for pat in patterns:
                        m = pat.search(line)
                        if not m:
                            continue
                        # Special filtering for hardcoded credentials
                        if rule_name in ("hardcoded-password", "hardcoded-api-key"):
                            cred_val = _extract_credential_value(line)
                            if cred_val is not None and _is_placeholder_credential(cred_val):
                                continue
                        snippet = line.strip()[:_MAX_LINE_SNIPPET]
                        result.findings.append(SASTFinding(
                            file=filepath,
                            line=line_no,
                            rule=rule_name,
                            severity=severity,
                            snippet=snippet,
                            detail=f"Pattern match: {pat.pattern[:80]}",
                        ))
                        break  # one match per rule per line is enough

        # --- Secret detection via curated gitleaks patterns ---
        secret_hits = _scan_secrets(content, source=filepath)
        # Map secret hits to line numbers
        for hit in secret_hits:
            line_no = self._find_line_for_context(content, hit.context)
            # Skip if it's a generic assignment that we already caught
            if hit.type == "Generic Secret Assignment":
                # Already covered by hardcoded-password/api-key rules
                continue
            result.findings.append(SASTFinding(
                file=filepath,
                line=line_no,
                rule=f"secret-{hit.type}",
                severity="high" if hit.fp_risk in ("low", "managed_db") else "medium",
                snippet=hit.context[:_MAX_LINE_SNIPPET],
                detail=f"Secret detected: {hit.type} (redacted: {hit.redacted})",
            ))

    @staticmethod
    def _find_line_for_context(content: str, context_snippet: str) -> int:
        """Best-effort: find the line number of a secret hit by searching for its context."""
        if not context_snippet:
            return 1
        # Try to find the context snippet in the content
        search = context_snippet[:40].replace("\n", " ")
        idx = content.find(search)
        if idx >= 0:
            return content[:idx].count("\n") + 1
        return 1


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def scan(path: str, language: str = "auto") -> SASTScanResult:
    """Scan a file or directory for vulnerability patterns.

    Shortcut for ``SASTScanner().scan(path, language)``.
    """
    return SASTScanner().scan(path, language=language)