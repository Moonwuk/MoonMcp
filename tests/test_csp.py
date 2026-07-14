"""CSP policy-strength analysis + its integration into audit_headers."""

from moonmcp.net.http import HttpResult
from moonmcp.recon.csp import analyze_csp, parse_policy
from moonmcp.recon.headers import audit_headers


def make_result(headers, status=200, url="https://t.example"):
    return HttpResult(url=url, final_url=url, status=status, reason="OK",
                      headers=headers, body=b"", elapsed_ms=1.0)


def _sev(weaknesses):
    return {directive: sev for directive, sev, _detail in weaknesses}


# -- parse_policy ------------------------------------------------------------
def test_parse_policy_splits_directives_and_keeps_source_case():
    d = parse_policy("default-src 'self'; script-src 'self' 'Nonce-AbC'")
    assert d["default-src"] == ["'self'"]
    assert d["script-src"] == ["'self'", "'Nonce-AbC'"]  # case preserved


def test_parse_policy_first_duplicate_wins():
    d = parse_policy("script-src 'self'; script-src *")
    assert d["script-src"] == ["'self'"]


# -- strength: strong policies stay 1.0 --------------------------------------
def test_strong_default_src_self_is_full_strength():
    assert analyze_csp("default-src 'self'")["strength"] == 1.0


def test_fully_hardened_policy_has_no_weaknesses():
    res = analyze_csp("default-src 'self'; object-src 'none'; base-uri 'none'")
    assert res["strength"] == 1.0
    assert res["weaknesses"] == []


# -- strength: bypassable policies are downgraded ----------------------------
def test_unsafe_inline_downgrades():
    res = analyze_csp("script-src 'self' 'unsafe-inline'")
    assert res["strength"] == 0.5
    assert _sev(res["weaknesses"])["script-src"] == "high"


def test_unsafe_inline_neutralised_by_nonce_is_not_penalised():
    res = analyze_csp("script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'")
    assert res["strength"] == 1.0
    # …but it's still surfaced as informational.
    assert any(sev == "info" for _d, sev, _t in res["weaknesses"])


def test_unsafe_eval_downgrades():
    assert analyze_csp("script-src 'self' 'unsafe-eval'")["strength"] == 0.7


def test_wildcard_script_source_downgrades():
    assert analyze_csp("script-src *")["strength"] == 0.5


def test_data_scheme_script_source_downgrades():
    assert analyze_csp("script-src 'self' data:")["strength"] == 0.7


def test_http_scheme_script_source_downgrades():
    assert analyze_csp("script-src 'self' http:")["strength"] == 0.85


def test_no_script_or_default_src_is_unrestricted():
    # A "CSP" that doesn't constrain scripts at all is the worthless-but-present case.
    res = analyze_csp("upgrade-insecure-requests")
    assert res["strength"] == 0.5
    assert _sev(res["weaknesses"])["script-src"] == "high"


def test_stacked_weaknesses_floor_at_zero():
    res = analyze_csp("default-src *; script-src 'unsafe-inline' 'unsafe-eval' *")
    assert res["strength"] == 0.0  # clamped, never negative


# -- hardening findings are report-only (no score impact) --------------------
def test_missing_base_uri_is_reported_but_not_penalised():
    res = analyze_csp("default-src 'self'")
    assert res["strength"] == 1.0
    assert _sev(res["weaknesses"]).get("base-uri") == "low"


def test_permissive_object_src_reported_low():
    res = analyze_csp("default-src 'self'; script-src 'self'; object-src *; base-uri 'none'")
    assert res["strength"] == 1.0  # object-src is hardening only
    assert _sev(res["weaknesses"])["object-src"] == "low"


# -- integration into audit_headers ------------------------------------------
def test_audit_headers_weak_csp_scores_below_strong_csp():
    base = [
        ("Strict-Transport-Security", "max-age=63072000"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
    ]
    strong = audit_headers(make_result(base + [("Content-Security-Policy", "default-src 'self'")]))
    weak = audit_headers(make_result(
        base + [("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'")]))
    assert strong.score == 100
    assert weak.score < strong.score          # worthless CSP is no longer full credit
    assert weak.csp_weaknesses                 # and the reasons are surfaced
    assert any(f.severity == "high" for f in weak.csp_weaknesses)


def test_audit_headers_strong_csp_still_grade_a():
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


def test_audit_headers_absent_csp_has_no_weaknesses_list():
    audit = audit_headers(make_result([("X-Content-Type-Options", "nosniff")]))
    assert audit.csp_weaknesses == []
    assert any(f.header == "content-security-policy" for f in audit.missing)
