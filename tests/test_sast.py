"""Tests for the SAST (static analysis) module."""

import os
import tempfile

from moonmcp.recon.sast import SASTScanner, scan


# Test fixture: Python file with SQLi + hardcoded password
_VULN_PY = '''\
"""Vulnerable test file."""
import sqlite3

DB_PASSWORD = "s3cr3t_p@ssw0rd_123"

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

PLACEHOLDER_PASS = "changeme"
'''

# Test fixture: JS file with XSS + deserialization
_VULN_JS = '''\
const div = document.getElementById("x");
div.innerHTML = req.body.html;
document.write(userInput);
eval(JSON.parse(req.body.payload));
'''

# Test fixture: Python with pickle deserialization
_VULN_DESER = '''\
import pickle

def load_data(data):
    return pickle.loads(data)
'''


def _write_tmp(content: str, suffix: str = ".py") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="sast_test_")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def test_sqli_and_hardcoded_password():
    """Scan Python file with SQLi + hardcoded password → 2 findings."""
    path = _write_tmp(_VULN_PY)
    try:
        result = scan(path, language="auto")
        rules = {f.rule for f in result.findings}
        # Must detect both
        assert "hardcoded-password" in rules, f"Expected hardcoded-password, got: {rules}"
        assert any(r.startswith("sqli-") for r in rules), f"Expected sqli rule, got: {rules}"
        # Must be exactly 2 (not counting placeholder)
        assert result.count == 2, f"Expected 2 findings, got {result.count}: {[f.rule for f in result.findings]}"
        # Placeholder should NOT be flagged
        snippets = [f.snippet for f in result.findings]
        assert not any("changeme" in s for s in snippets), "Placeholder was flagged"
    finally:
        os.unlink(path)


def test_xss_detection():
    """Scan JS file with XSS patterns."""
    path = _write_tmp(_VULN_JS, suffix=".js")
    try:
        result = scan(path, language="javascript")
        rules = {f.rule for f in result.findings}
        assert "xss-innerhtml" in rules, f"Expected xss-innerhtml, got: {rules}"
        assert "xss-document-write" in rules, f"Expected xss-document-write, got: {rules}"
        assert "xss-eval-userinput" in rules, f"Expected xss-eval-userinput, got: {rules}"
    finally:
        os.unlink(path)


def test_deserialization_detection():
    """Scan Python file with pickle.loads."""
    path = _write_tmp(_VULN_DESER)
    try:
        result = scan(path, language="auto")
        rules = {f.rule for f in result.findings}
        assert "deserialization-pickle" in rules, f"Expected deserialization-pickle, got: {rules}"
    finally:
        os.unlink(path)


def test_placeholder_not_flagged():
    """Placeholder credentials should not be flagged."""
    content = '''
PASSWORD = "changeme"
API_KEY = "your_api_key"
SECRET = "example"
'''
    path = _write_tmp(content)
    try:
        result = scan(path, language="python")
        rules = {f.rule for f in result.findings}
        assert "hardcoded-password" not in rules, f"Placeholder was flagged: {rules}"
    finally:
        os.unlink(path)


def test_directory_scan():
    """Scanning a directory should work recursively."""
    tmpdir = tempfile.mkdtemp(prefix="sast_dir_")
    try:
        with open(os.path.join(tmpdir, "a.py"), "w") as f:
            f.write('query = "SELECT * FROM t WHERE id = " + user_id\n')
        with open(os.path.join(tmpdir, "b.js"), "w") as f:
            f.write('document.write(input);\n')
        os.makedirs(os.path.join(tmpdir, "subdir"), exist_ok=True)
        with open(os.path.join(tmpdir, "subdir", "c.py"), "w") as f:
            f.write('password = "hardcoded_secret_123"\n')
        result = scan(tmpdir, language="auto")
        assert result.files_scanned == 3, f"Expected 3 files, got {result.files_scanned}"
        assert result.count >= 3, f"Expected >=3 findings, got {result.count}"
        files_scanned = {f.file for f in result.findings}
        assert any("a.py" in f for f in files_scanned)
        assert any("b.js" in f for f in files_scanned)
        assert any("c.py" in f for f in files_scanned)
    finally:
        import shutil
        shutil.rmtree(tmpdir)


def test_result_summary():
    """Result summary should have correct structure."""
    path = _write_tmp(_VULN_PY)
    try:
        result = scan(path, language="auto")
        s = result.summary()
        assert s["total_findings"] == 2
        assert s["files_scanned"] == 1
        assert "by_severity" in s
        assert "by_rule" in s
        assert s["by_severity"].get("high") == 2
    finally:
        os.unlink(path)


def test_nonexistent_path():
    """Scanning a nonexistent path should return an error."""
    result = scan("/nonexistent/path/xyz.py")
    assert result.files_scanned == 0
    assert "/nonexistent/path/xyz.py" in result.errors


def test_finding_has_required_fields():
    """Each finding must have file, line, rule, severity, snippet."""
    path = _write_tmp(_VULN_PY)
    try:
        result = scan(path, language="auto")
        for f in result.findings:
            d = f.to_dict()
            assert "file" in d
            assert "line" in d
            assert "rule" in d
            assert "severity" in d
            assert "snippet" in d
            assert isinstance(d["line"], int)
            assert d["line"] > 0
    finally:
        os.unlink(path)