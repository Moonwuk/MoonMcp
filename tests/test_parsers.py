"""Offline tests for pure parsing/analysis logic (no network)."""


from moonmcp.intel.cve import _parse_vuln
from moonmcp.net.http import HttpResult
from moonmcp.net.ports import parse_ports
from moonmcp.recon.fingerprint import fingerprint
from moonmcp.recon.headers import audit_headers
from moonmcp.recon.subdomains import _clean


def make_result(headers, body=b"", status=200, url="https://t.example"):
    return HttpResult(
        url=url, final_url=url, status=status, reason="OK",
        headers=headers, body=body, elapsed_ms=1.0,
    )


# --- ports ---------------------------------------------------------------
def test_parse_ports_spec():
    assert parse_ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]
    assert parse_ports("443-441") == [441, 442, 443]  # reversed range normalised
    assert parse_ports("70000,0,80") == [80]  # out-of-range dropped
    assert parse_ports("top") == parse_ports(None)
    assert len(parse_ports("top")) > 20


# --- fingerprint ---------------------------------------------------------
def test_fingerprint_detects_stack_no_duplicates():
    headers = [
        ("Server", "nginx/1.25.1"),
        ("X-Powered-By", "PHP/8.2.1"),
        ("Set-Cookie", "PHPSESSID=x; Path=/"),
    ]
    body = b"<html><head><title>Hi</title></head><body>wp-content react-root</body></html>"
    fp = fingerprint(make_result(headers, body))
    names = [t.name for t in fp.technologies]
    assert names.count("PHP") == 1  # deduped
    assert "nginx" in names
    assert "WordPress" in names
    assert "React" in names
    assert fp.title == "Hi"
    php = next(t for t in fp.technologies if t.name == "PHP")
    assert php.version == "8.2.1"  # versioned match preferred over cookie match


def test_fingerprint_cloudflare_via_header():
    fp = fingerprint(make_result([("CF-RAY", "abc-DFW")]))
    assert any(t.name == "Cloudflare" for t in fp.technologies)


# --- header audit --------------------------------------------------------
def test_header_audit_grades_and_flags():
    good = [
        ("Strict-Transport-Security", "max-age=63072000"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
    ]
    audit = audit_headers(make_result(good))
    assert audit.grade == "A"
    assert audit.score == 100
    assert audit.missing == []

    bad = [("Server", "Apache/2.4.1"), ("Set-Cookie", "id=1; Path=/")]
    audit2 = audit_headers(make_result(bad))
    assert audit2.grade == "F"
    assert any(f.header == "strict-transport-security" for f in audit2.missing)
    assert any(f.header == "server" for f in audit2.info_leaks)
    # Secure + HttpOnly + SameSite all missing over HTTPS.
    assert len(audit2.cookie_issues) == 3


# --- subdomain cleaning --------------------------------------------------
def test_subdomain_clean():
    assert _clean("API.Example.com", "example.com") == "api.example.com"
    assert _clean("*.example.com", "example.com") == "example.com"
    assert _clean("sub.example.com.", "example.com") == "sub.example.com"
    assert _clean("evil.com", "example.com") is None
    assert _clean("not a host", "example.com") is None


# --- CVE parsing ---------------------------------------------------------
def test_cve_parse_from_nvd_fixture():
    fixture = {
        "cve": {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T10:15:09.143",
            "descriptions": [
                {"lang": "en", "value": "Apache Log4j2 JNDI features..."},
                {"lang": "es", "value": "ignored"},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL",
                                  "vectorString": "CVSS:3.1/AV:N/AC:L/..."}}
                ]
            },
            "weaknesses": [
                {"description": [{"value": "CWE-502"}, {"value": "CWE-400"}]}
            ],
            "references": [{"url": "https://example.com/advisory"}],
        }
    }
    rec = _parse_vuln(fixture)
    assert rec.id == "CVE-2021-44228"
    assert rec.cvss_score == 10.0
    assert rec.cvss_severity == "CRITICAL"
    assert rec.cwe == ["CWE-502", "CWE-400"]
    assert rec.description.startswith("Apache Log4j2")
    assert rec.references == ["https://example.com/advisory"]


def test_jsonl_parse():
    from moonmcp.external.cli import parse_jsonl

    text = '{"a":1}\n\ngarbage\n{"b":2}\n'
    rows = parse_jsonl(text)
    assert rows == [{"a": 1}, {"b": 2}]
