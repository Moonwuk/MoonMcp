import pytest

from moonmcp.scope import ScopeError, ScopeManager, normalize_target


def test_normalize_target_variants():
    assert normalize_target("https://www.Example.com/path?a=b") == "www.example.com"
    assert normalize_target("Example.COM.") == "example.com"
    assert normalize_target("example.com:8443") == "example.com"
    assert normalize_target("http://[::1]:80/") == "::1"
    assert normalize_target("[2001:db8::1]:443") == "2001:db8::1"
    assert normalize_target("2001:db8::1") == "2001:db8::1"


def test_apex_entry_matches_apex_and_subdomains():
    s = ScopeManager()
    s.add("example.com")
    assert s.is_in_scope("example.com")
    assert s.is_in_scope("api.example.com")
    assert s.is_in_scope("a.b.example.com")
    assert not s.is_in_scope("notexample.com")
    assert not s.is_in_scope("example.com.evil.com")


def test_wildcard_entry_is_subdomains_only():
    s = ScopeManager()
    s.add("*.example.com")
    assert s.is_in_scope("api.example.com")
    assert not s.is_in_scope("example.com")


def test_exact_host_entry():
    s = ScopeManager()
    s.add("api.example.com")
    assert s.is_in_scope("api.example.com")
    # A more-specific host entry does not authorise siblings or the apex.
    assert not s.is_in_scope("www.example.com")
    # ...but it authorises deeper labels under that host.
    assert s.is_in_scope("v2.api.example.com")


def test_exclusion_overrides_inclusion():
    s = ScopeManager()
    s.add("example.com")
    s.exclude("admin.example.com")
    assert not s.is_in_scope("admin.example.com")
    assert s.is_in_scope("www.example.com")


def test_ip_and_cidr():
    # block_private off: this test exercises CIDR matching on a private range.
    s = ScopeManager(block_private=False)
    s.add("10.0.0.0/8")
    s.add("203.0.113.10")
    assert s.is_in_scope("10.1.2.3")
    assert s.is_in_scope("203.0.113.10")
    assert not s.is_in_scope("8.8.8.8")


def test_empty_scope_blocks_when_enforced():
    s = ScopeManager(enforce=True)
    ok, reason = s.evaluate("example.com")
    assert not ok
    assert "no scope configured" in reason


def test_disabled_enforcement_allows_all_but_denies():
    s = ScopeManager(enforce=False)
    assert s.is_in_scope("anything.com")
    s.exclude("blocked.com")
    assert not s.is_in_scope("blocked.com")


def test_check_raises_and_returns_host():
    s = ScopeManager()
    s.add("example.com")
    assert s.check("https://api.example.com/x") == "api.example.com"
    with pytest.raises(ScopeError):
        s.check("evil.com")


def test_block_private_addresses_by_default():
    s = ScopeManager(enforce=True, block_private=True)
    s.add("10.0.0.0/8")          # even an explicit allow does not override the guard
    s.add("127.0.0.1")
    s.add("169.254.169.254")     # cloud metadata
    for ip in ("10.1.2.3", "127.0.0.1", "169.254.169.254", "192.168.1.1", "0.0.0.0"):
        ok, reason = s.evaluate(ip)
        assert not ok, ip
        assert "private/reserved" in reason


def test_block_private_can_be_disabled_for_internal_testing():
    s = ScopeManager(enforce=True, block_private=False)
    s.add("10.0.0.0/8")
    assert s.is_in_scope("10.1.2.3")
    assert not s.is_in_scope("11.0.0.1")  # still scoped, just not private-blocked


def test_public_ip_unaffected_by_private_guard():
    s = ScopeManager(enforce=True, block_private=True)
    s.add("8.8.8.0/24")
    assert s.is_in_scope("8.8.8.8")


def test_obfuscated_ip_literals_are_blocked():
    # decimal / hex / octal / short-form encodings of 127.0.0.1 must not slip past.
    s = ScopeManager(enforce=True, block_private=True)
    for form in ("2130706433", "0x7f000001", "0177.0.0.1", "127.1", "017700000001"):
        ok, reason = s.evaluate(form)
        assert not ok, form
        assert "private/reserved" in reason, form
    # IPv4-mapped IPv6 loopback too
    assert s.blocked_connect_reason("::ffff:127.0.0.1") is not None


def test_blocked_connect_reason_resolves_hostnames():
    # a hostname that RESOLVES to an internal IP must be blocked at connect time,
    # even though it is not an IP literal and is nominally in scope.
    resolved = {"internal.example.com": ["10.0.0.5"],
                "metadata.example.com": ["169.254.169.254"],
                "public.example.com": ["93.184.216.34"]}
    s = ScopeManager(enforce=True, block_private=True,
                     resolver=lambda h: resolved.get(h, []))
    s.add("example.com")
    assert s.blocked_connect_reason("internal.example.com") is not None
    assert s.blocked_connect_reason("metadata.example.com") is not None
    assert s.blocked_connect_reason("public.example.com") is None
    # disabling the guard makes it a no-op
    s.block_private = False
    assert s.blocked_connect_reason("internal.example.com") is None


def test_blocked_connect_reason_unresolvable_is_open():
    # can't resolve → can't connect anyway → don't hard-block
    s = ScopeManager(block_private=True, resolver=lambda h: [])
    assert s.blocked_connect_reason("nxdomain.invalid") is None


def test_remove_entry():
    s = ScopeManager()
    s.add("example.com")
    assert s.is_in_scope("example.com")
    assert s.remove("example.com")
    assert not s.is_in_scope("example.com")


def test_resolve_pin_resolves_once_and_pins():
    from moonmcp.scope import ScopeManager
    # a public IP literal pins to itself
    s = ScopeManager(block_private=True)
    assert s.resolve_pin("93.184.216.34") == ("93.184.216.34", None)
    # a private/metadata literal is blocked, no pin
    ip, reason = s.resolve_pin("169.254.169.254")
    assert ip is None and reason is not None
    # a hostname resolving to a public IP pins to that address
    pub = ScopeManager(block_private=True, resolver=lambda h: ["8.8.8.8"])
    assert pub.resolve_pin("host.example") == ("8.8.8.8", None)
    # a hostname that rebinds to a private IP is blocked
    priv = ScopeManager(block_private=True, resolver=lambda h: ["127.0.0.1"])
    ip2, r2 = priv.resolve_pin("rebind.example")
    assert ip2 is None and r2 is not None
    # block_private off: neither check nor pin (authorised internal testing)
    off = ScopeManager(block_private=False, resolver=lambda h: ["127.0.0.1"])
    assert off.resolve_pin("anything.example") == (None, None)
    # blocked_connect_reason is the thin (reason-only) wrapper over resolve_pin
    assert priv.blocked_connect_reason("rebind.example") is not None
    assert pub.blocked_connect_reason("host.example") is None
