"""Adversarial regression guard for the scope / SSRF safety core.

These pin the boundary behaviours an attacker probes — obfuscated & IPv6-encoded
private IPs, userinfo host confusion, domain suffix confusion, wildcard apex
handling, and "private wins over a broad in-scope CIDR". They passed when written;
their job is to fail loudly if a future refactor of scope.py silently weakens the
guard (e.g. an "optimised" reserved-range check that lets NAT64 through).
"""

import pytest

from moonmcp.scope import ScopeManager, is_blocked_address, normalize_target


# --- normalize_target: the host the scope check will actually judge --------------
@pytest.mark.parametrize("raw,host", [
    ("HTTP://EXAMPLE.COM/x", "example.com"),               # scheme + host lower-cased
    ("http://user:pass@example.com:8080/p", "example.com"),  # userinfo + port stripped
    ("http://example.com.", "example.com"),                 # trailing dot stripped
    ("http://[::1]:8080/x", "::1"),                         # bracketed IPv6 + port
    ("example.com:443", "example.com"),                     # host:port
    ("[2001:db8::1]:80", "2001:db8::1"),                   # bracketed IPv6 literal
    ("  http://a.example  ", "a.example"),                 # surrounding whitespace
    # userinfo host-confusion: the REAL host is after the @, and that is what must
    # be scope-checked — a "legit.example@evil" cannot smuggle traffic to evil.
    ("http://legit.example@evil.example/x", "evil.example"),
])
def test_normalize_target_extracts_the_real_host(raw, host):
    assert normalize_target(raw) == host


@pytest.mark.parametrize("bad", [None, "", "   "])
def test_normalize_target_rejects_empty(bad):
    with pytest.raises(ValueError):
        normalize_target(bad)


# --- is_blocked_address: every private/reserved encoding an SSRF payload uses -----
@pytest.mark.parametrize("addr", [
    # obfuscated IPv4 loopback / metadata
    "127.0.0.1", "2130706433", "0x7f000001", "017700000001", "127.1", "0177.0.0.1",
    "169.254.169.254", "2852039166",           # link-local metadata (dotted + decimal)
    # RFC1918 + CGNAT + benchmark
    "10.0.0.1", "192.168.1.1", "172.16.0.1", "100.100.100.200", "100.64.0.1", "198.18.0.1",
    "0.0.0.0",
    # IPv6 loopback / ULA / link-local / unspecified
    "::1", "fc00::1", "fd12:3456::1", "fe80::1", "::",
    # IPv4 embedded in IPv6: mapped, compatible, and NAT64 well-known prefix
    "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::127.0.0.1",
    "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
])
def test_blocked_addresses_are_blocked(addr):
    assert is_blocked_address(addr) is True, addr


@pytest.mark.parametrize("addr", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111",
])
def test_public_addresses_are_not_blocked(addr):
    assert is_blocked_address(addr) is False, addr


def test_hostnames_are_not_blocked_here():
    # is_blocked_address only judges IP literals; hostname→IP is guarded at connect.
    assert is_blocked_address("example.com") is False
    assert is_blocked_address("metadata.google.internal") is False


# --- domain suffix confusion ------------------------------------------------------
def test_apex_entry_rejects_suffix_confusion():
    s = ScopeManager()
    s.add("example.com")
    assert s.is_in_scope("example.com") is True
    assert s.is_in_scope("api.example.com") is True
    for evil in ("notexample.com", "example.com.evil.com", "exampleXcom", "evil-example.com"):
        assert s.is_in_scope(evil) is False, evil


def test_wildcard_entry_excludes_the_apex():
    s = ScopeManager()
    s.add("*.example.com")
    assert s.is_in_scope("example.com") is False       # apex NOT covered by *.
    assert s.is_in_scope("api.example.com") is True
    assert s.is_in_scope("a.b.example.com") is True


def test_exclusion_always_wins_over_inclusion():
    s = ScopeManager()
    s.add("example.com")
    s.exclude("admin.example.com")
    assert s.is_in_scope("admin.example.com") is False
    assert s.is_in_scope("app.example.com") is True


# --- the SSRF guard beats a broad in-scope CIDR ----------------------------------
def test_private_ip_blocked_even_when_a_broad_cidr_is_in_scope():
    s = ScopeManager(block_private=True)
    s.add("10.0.0.0/8")
    # in the allowlist by CIDR, but the SSRF guard refuses it anyway
    assert s.is_in_scope("10.1.2.3") is False
    # disabling the guard (authorised internal engagement) lets it through
    s2 = ScopeManager(block_private=False)
    s2.add("10.0.0.0/8")
    assert s2.is_in_scope("10.1.2.3") is True


def test_resolve_pin_pins_public_and_blocks_private():
    s = ScopeManager(block_private=True, resolver=lambda h: ["93.184.216.34"])
    s.add("good.example")
    assert s.resolve_pin("good.example") == (None, "93.184.216.34")
    s.add("bad.example")
    s._resolver = lambda h: ["169.254.169.254"]
    reason, pin = s.resolve_pin("bad.example")
    assert reason is not None and pin is None
