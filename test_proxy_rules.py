#!/usr/bin/env python3
"""Tests for proxy_rules module — ProxyRule + ProxyRuleEngine."""
import sys
import os

# Ensure the moonmcp package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "moonmcp"))

from moonmcp.web.proxy_rules import (
    ProxyRule, ProxyRuleEngine,
    bugbounty_header_rule, ua_spoof_rule, token_rotation_rule,
    url_rewrite_rule, body_rewrite_rule, header_rewrite_rule,
    redirect_intercept_rule,
)


def test_add_header_rule():
    """Rule type 1: auto-add X-BugBounty header."""
    eng = ProxyRuleEngine()
    rule = eng.add_rule(bugbounty_header_rule("X-BugBounty: authorized-testing"))
    assert rule.match_type == "add_header"
    assert rule.header_name == "X-BugBounty"
    assert rule.replace_pattern == "authorized-testing"

    req = {"url": "https://example.com/api", "method": "GET", "headers": {}, "body": ""}
    modified = eng.apply_rules(req)
    assert modified["headers"]["X-BugBounty"] == "authorized-testing"
    assert "add_header" in modified["_applied_rules"][0]
    # original request unchanged
    assert "X-BugBounty" not in req["headers"]
    print("✓ test_add_header_rule passed")


def test_url_rewrite():
    """Rule type 2: match & replace in URL."""
    eng = ProxyRuleEngine()
    eng.add_rule(url_rewrite_rule(r"example\.com", "evil.com"))

    req = {"url": "https://example.com/api/v1", "method": "GET", "headers": {}, "body": ""}
    modified = eng.apply_rules(req)
    assert modified["url"] == "https://evil.com/api/v1"
    print("✓ test_url_rewrite passed")


def test_body_rewrite():
    """Rule type 2b: match & replace in body."""
    eng = ProxyRuleEngine()
    eng.add_rule(body_rewrite_rule(r"old_secret", "new_secret"))

    req = {"url": "https://example.com", "method": "POST", "headers": {}, "body": "token=old_secret&data=x"}
    modified = eng.apply_rules(req)
    assert modified["body"] == "token=new_secret&data=x"
    print("✓ test_body_rewrite passed")


def test_header_rewrite():
    """Rule type 3: match & replace header value."""
    eng = ProxyRuleEngine()
    eng.add_rule(header_rewrite_rule(r"X-Forwarded-For", replacement="10.0.0.1"))

    req = {"url": "https://example.com", "method": "GET",
           "headers": {"X-Forwarded-For": "1.2.3.4"}, "body": ""}
    modified = eng.apply_rules(req)
    assert modified["headers"]["X-Forwarded-For"] == "10.0.0.1"
    print("✓ test_header_rewrite passed")


def test_redirect_intercept():
    """Rule type 4: intercept redirect — rewrite Location."""
    eng = ProxyRuleEngine()
    eng.add_rule(redirect_intercept_rule(r"example\.com", "evil.com"))

    req = {"url": "https://example.com/login", "method": "GET", "headers": {}, "body": ""}
    resp = {"headers": {"Location": "https://example.com/dashboard"}}
    modified = eng.apply_rules(req, response=resp)
    assert resp["headers"]["Location"] == "https://evil.com/dashboard"
    print("✓ test_redirect_intercept passed")


def test_token_rotation():
    """Rule type 5: token rotation — Bearer token replaced."""
    eng = ProxyRuleEngine()

    # static replacement
    eng.add_rule(ProxyRule(
        match_type="token",
        replace_pattern="NEW_TOKEN_VALUE",
    ))
    req = {"url": "https://example.com/api", "method": "GET",
           "headers": {"Authorization": "Bearer OLD_TOKEN"}, "body": ""}
    modified = eng.apply_rules(req)
    assert modified["headers"]["Authorization"] == "Bearer NEW_TOKEN_VALUE"
    print("✓ test_token_rotation (static) passed")

    # dynamic provider
    eng.clear()
    counter = [0]
    def provider():
        counter[0] += 1
        return f"ROT_{counter[0]}"

    eng.add_rule(token_rotation_rule(provider))
    req1 = {"url": "https://example.com", "method": "GET",
            "headers": {"Authorization": "Bearer FIRST"}, "body": ""}
    m1 = eng.apply_rules(req1)
    assert m1["headers"]["Authorization"] == "Bearer ROT_1"
    req2 = {"url": "https://example.com", "method": "GET",
            "headers": {"Authorization": "Bearer SECOND"}, "body": ""}
    m2 = eng.apply_rules(req2)
    assert m2["headers"]["Authorization"] == "Bearer ROT_2"
    print("✓ test_token_rotation (dynamic) passed")


def test_ua_spoofing():
    """Rule type 6: User-Agent spoofing."""
    eng = ProxyRuleEngine()
    eng.add_rule(ua_spoof_rule("Mozilla/5.0 (Custom; Hacker) Browser/1.0"))

    req = {"url": "https://example.com", "method": "GET",
           "headers": {"User-Agent": "curl/8.0"}, "body": ""}
    modified = eng.apply_rules(req)
    assert modified["headers"]["User-Agent"] == "Mozilla/5.0 (Custom; Hacker) Browser/1.0"
    print("✓ test_ua_spoofing passed")


def test_method_override():
    """Method match & replace."""
    eng = ProxyRuleEngine()
    eng.add_rule(ProxyRule(match_type="method", match_pattern="GET", replace_pattern="POST"))

    req = {"url": "https://example.com", "method": "GET", "headers": {}, "body": ""}
    modified = eng.apply_rules(req)
    assert modified["method"] == "POST"
    print("✓ test_method_override passed")


def test_scope_filter():
    """Rules with scope_filter only match scoped hosts."""
    eng = ProxyRuleEngine()
    eng.add_rule(ProxyRule(
        match_type="add_header",
        header_name="X-Test",
        replace_pattern="yes",
        scope_filter="example.com",
    ))
    eng.add_rule(ProxyRule(
        match_type="add_header",
        header_name="X-All",
        replace_pattern="yes",
    ))

    # scoped
    req1 = {"url": "https://example.com/api", "method": "GET", "headers": {}, "body": ""}
    m1 = eng.apply_rules(req1)
    assert "X-Test" in m1["headers"]
    assert "X-All" in m1["headers"]

    # out of scope for X-Test
    req2 = {"url": "https://other.com/api", "method": "GET", "headers": {}, "body": ""}
    m2 = eng.apply_rules(req2)
    assert "X-Test" not in m2["headers"]
    assert "X-All" in m2["headers"]
    print("✓ test_scope_filter passed")


def test_disabled_rule():
    """Disabled rules are not applied."""
    eng = ProxyRuleEngine()
    eng.add_rule(ProxyRule(
        match_type="add_header",
        header_name="X-Disabled",
        replace_pattern="no",
        enabled=False,
    ))
    req = {"url": "https://example.com", "method": "GET", "headers": {}, "body": ""}
    m = eng.apply_rules(req)
    assert "X-Disabled" not in m["headers"]
    assert m["_applied_rules"] == []
    print("✓ test_disabled_rule passed")


def test_remove_rule():
    """Remove a rule by id."""
    eng = ProxyRuleEngine()
    rule = eng.add_rule(ProxyRule(match_type="add_header", header_name="X-Temp", replace_pattern="v"))
    assert eng.remove_rule(rule.id) is True
    assert eng.remove_rule("nonexistent") is False
    req = {"url": "https://example.com", "method": "GET", "headers": {}, "body": ""}
    m = eng.apply_rules(req)
    assert "X-Temp" not in m["headers"]
    print("✓ test_remove_rule passed")


def test_priority_ordering():
    """Lower priority fires first — verify ordering via applied_rules list."""
    eng = ProxyRuleEngine()
    eng.add_rule(ProxyRule(match_type="add_header", header_name="X-Second", replace_pattern="2", priority=10))
    eng.add_rule(ProxyRule(match_type="add_header", header_name="X-First", replace_pattern="1", priority=-10))
    req = {"url": "https://example.com", "method": "GET", "headers": {}, "body": ""}
    m = eng.apply_rules(req)
    # first applied rule should be X-First (priority -10)
    assert "X-First" in m["_applied_rules"][0]
    assert "X-Second" in m["_applied_rules"][1]
    print("✓ test_priority_ordering passed")


def test_combined_rules():
    """Multiple rules applied together — real-world scenario."""
    eng = ProxyRuleEngine()
    eng.add_rule(bugbounty_header_rule("X-BugBounty: researcher-authorized"))
    eng.add_rule(ua_spoof_rule("Mozilla/5.0 (PenTest)"))
    eng.add_rule(url_rewrite_rule(r"/api/v1/", "/api/v2/"))
    eng.add_rule(body_rewrite_rule(r"token=\w+", "token=HACKED"))

    req = {
        "url": "https://target.com/api/v1/login",
        "method": "POST",
        "headers": {"Authorization": "Bearer old"},
        "body": "token=oldsecret&user=admin",
    }
    m = eng.apply_rules(req)

    assert m["headers"]["X-BugBounty"] == "researcher-authorized"
    assert m["headers"]["User-Agent"] == "Mozilla/5.0 (PenTest)"
    assert m["url"] == "https://target.com/api/v2/login"
    assert m["body"] == "token=HACKED&user=admin"
    assert len(m["_applied_rules"]) == 4
    print("✓ test_combined_rules passed")


def test_original_not_mutated():
    """The original request dict is not mutated."""
    eng = ProxyRuleEngine()
    eng.add_rule(bugbounty_header_rule("X-BugBounty: test"))
    orig_headers = {"Accept": "*/*"}
    req = {"url": "https://example.com", "method": "GET", "headers": orig_headers, "body": ""}
    eng.apply_rules(req)
    assert "X-BugBounty" not in orig_headers
    print("✓ test_original_not_mutated passed")


if __name__ == "__main__":
    tests = [
        test_add_header_rule,
        test_url_rewrite,
        test_body_rewrite,
        test_header_rewrite,
        test_redirect_intercept,
        test_token_rotation,
        test_ua_spoofing,
        test_method_override,
        test_scope_filter,
        test_disabled_rule,
        test_remove_rule,
        test_priority_ordering,
        test_combined_rules,
        test_original_not_mutated,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"✗ {t.__name__} FAILED: {e}")
            failed += 1
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)