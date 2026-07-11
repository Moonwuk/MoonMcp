"""Authorization scope — MoonMCP's core safety guardrail.

Bug-bounty and pentest work is only legal against assets you are authorised to
test.  Most recon MCP servers in the wild expose raw scanning primitives with no
notion of scope, which makes it trivially easy to point them at the wrong host.
MoonMCP inverts that: every packet-sending tool must pass a scope check first.

Scope is expressed as a list of entries:

* ``example.com``      — the apex **and** every subdomain (``*.example.com``).
* ``*.example.com``    — subdomains only (not the apex).
* ``api.example.com``  — that exact host only.
* ``203.0.113.10``     — a single IP address.
* ``10.0.0.0/8``       — a CIDR range (IPv4 or IPv6).

Exclusions (out-of-scope entries) always win over inclusions, mirroring how real
bug-bounty programs carve exceptions out of a wildcard.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit


class ScopeError(PermissionError):
    """Raised when a tool is asked to touch an out-of-scope target."""


def normalize_target(raw: str) -> str:
    """Extract a bare host (or IP) from user input.

    Accepts URLs (``https://a.b/c``), ``host:port``, bracketed IPv6, or a plain
    hostname/IP and returns just the host, lower-cased and stripped of a trailing
    dot.  Raises :class:`ValueError` on empty input.
    """

    if raw is None:
        raise ValueError("empty target")
    value = raw.strip()
    if not value:
        raise ValueError("empty target")

    # If it looks like a URL, let urlsplit do the heavy lifting.
    if "://" in value:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if host:
            return host.rstrip(".").lower()
        value = parsed.path  # fall through with whatever remained

    # Bracketed IPv6 literal, optionally with a port: [::1]:8080
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            return value[1:end].strip().rstrip(".").lower()

    # Bare IPv6 (contains multiple colons and no brackets) — leave as-is.
    if value.count(":") > 1:
        try:
            ipaddress.ip_address(value)
            return value.lower()
        except ValueError:
            pass  # not a bare IPv6, treat the last colon as a port separator

    # host:port  → strip the port
    if ":" in value:
        value = value.rsplit(":", 1)[0]

    return value.rstrip(".").lower()


def canonical_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return an IP address object if *host* is any IP literal, else ``None``.

    Crucially this also recognises the *obfuscated* IPv4 forms an SSRF attacker
    uses to slip past a naive dotted-quad check — decimal (``2130706433``),
    hex (``0x7f000001``), octal (``017700000001``) and short (``127.1``) — by
    routing numeric-looking input through :func:`socket.inet_aton`.
    """

    h = host.strip()
    if not h:
        return None
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Legacy/obfuscated IPv4 literal — only attempt when the token is numeric-ish
    # (hex digits, 'x', dots) so real hostnames like "cafe.example" aren't coerced.
    if all(c in "0123456789abcdefABCDEFxX." for c in h):
        try:
            packed = socket.inet_aton(h)
        except OSError:
            return None
        return ipaddress.IPv4Address(packed)
    return None


def _ip_is_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if *addr* is in a private/reserved range that is off-limits by default."""

    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:  # ::ffff:127.0.0.1 must be judged as its IPv4 form
        addr = mapped
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def is_blocked_address(host: str) -> bool:
    """True if *host* is an IP literal (including obfuscated IPv4 encodings) in a
    private/reserved/loopback/link-local range that should be off-limits by
    default (SSRF guard).

    Non-IP hostnames return False here — hostname→IP resolution is guarded at
    connect time by :meth:`ScopeManager.blocked_connect_reason`.
    """

    ip = canonical_ip(host)
    return False if ip is None else _ip_is_blocked(ip)


def _as_network(entry: str) -> ipaddress._BaseNetwork | None:
    """Return an ip_network for an IP/CIDR entry, else None."""

    try:
        if "/" in entry:
            return ipaddress.ip_network(entry, strict=False)
        addr = ipaddress.ip_address(entry)
        return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
    except ValueError:
        return None


@dataclass
class _DomainRule:
    """A host-matching rule derived from a scope entry."""

    host: str          # normalised host, e.g. "example.com"
    subdomains: bool   # match *.host
    apex: bool         # match host itself

    def matches(self, target: str) -> bool:
        if self.apex and target == self.host:
            return True
        if self.subdomains and target.endswith("." + self.host):
            return True
        return False


class ScopeManager:
    """Holds the in-scope allowlist / out-of-scope denylist and checks targets."""

    def __init__(self, enforce: bool = True, block_private: bool = True,
                 resolver: Callable[[str], list[str]] | None = None) -> None:
        self.enforce = enforce
        self.block_private = block_private
        # resolver(host) -> list of IP strings; defaults to the system resolver.
        # Injectable so the SSRF guard can be tested without real DNS.
        self._resolver = resolver
        self._allow_domains: list[_DomainRule] = []
        self._deny_domains: list[_DomainRule] = []
        self._allow_nets: list[ipaddress._BaseNetwork] = []
        self._deny_nets: list[ipaddress._BaseNetwork] = []
        self._raw_allow: list[str] = []
        self._raw_deny: list[str] = []

    def _resolve(self, host: str) -> list[str]:
        """Resolve *host* to a list of IP strings.

        A genuinely *unresolvable* host (NXDOMAIN / bad name) returns ``[]`` — that
        is safe to allow because the caller cannot connect to it either. But a
        resolver that raises an **unexpected** error (a custom resolver, a transient
        failure) must NOT be silently treated as "no addresses" — the caller might
        still resolve+connect to a private IP — so that propagates and the SSRF
        guard fails **closed** on it."""

        if self._resolver is not None:
            return list(self._resolver(host))  # let unexpected errors propagate → fail closed
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError):
            return []  # unresolvable / malformed host → cannot be connected to → safe
        return [str(ai[4][0]) for ai in infos]

    def blocked_connect_reason(self, target: str) -> str | None:
        """SSRF guard applied at *connect* time: return a reason string if
        connecting to *target* is unsafe, else ``None``.

        Unlike :meth:`evaluate` (which only sees IP literals), this resolves a
        hostname and blocks it if **any** resolved address is private/reserved —
        closing the "in-scope hostname that points at 127.0.0.1 / cloud-metadata"
        SSRF hole. No-op when ``block_private`` is disabled.
        """

        if not self.block_private:
            return None
        try:
            host = normalize_target(target)
        except ValueError:
            return None
        ip = canonical_ip(host)
        if ip is not None:
            if _ip_is_blocked(ip):
                return f"{host} is a private/reserved address ({ip}) blocked by the SSRF guard"
            return None
        try:
            resolved = self._resolve(host)
        except Exception:
            # We could not verify where this host points; fail closed rather than
            # let a resolver error open a private-IP path (defence against a resolver
            # that disagrees with the one urllib/socket will use at connect time).
            return (f"{host} could not be resolved for the SSRF guard — blocked (fail-closed; "
                    "set MOONMCP_BLOCK_PRIVATE=0 for authorised internal testing)")
        for raw in resolved:
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if _ip_is_blocked(addr):
                return (
                    f"{host} resolves to {addr}, a private/reserved address — blocked by the "
                    "SSRF guard (set MOONMCP_BLOCK_PRIVATE=0 for authorised internal testing)"
                )
        return None

    # -- mutation ----------------------------------------------------------
    @staticmethod
    def _parse_domain(entry: str) -> _DomainRule:
        e = entry.strip().rstrip(".").lower()
        if e.startswith("*."):
            return _DomainRule(host=e[2:], subdomains=True, apex=False)
        # A bare apex entry implies the apex plus all its subdomains, matching
        # how bug-bounty programs usually mean "example.com".
        return _DomainRule(host=e, subdomains=True, apex=True)

    def _add(self, entry: str, *, deny: bool) -> str:
        entry = entry.strip()
        if not entry:
            return ""
        net = _as_network(entry)
        if net is not None:
            (self._deny_nets if deny else self._allow_nets).append(net)
        else:
            rule = self._parse_domain(entry)
            (self._deny_domains if deny else self._allow_domains).append(rule)
        raw = self._raw_deny if deny else self._raw_allow
        norm = entry.lower()
        if norm not in raw:
            raw.append(norm)
        return entry

    def add(self, entry: str) -> str:
        """Add an in-scope entry (domain / IP / CIDR)."""
        return self._add(entry, deny=False)

    def exclude(self, entry: str) -> str:
        """Add an out-of-scope entry that overrides the allowlist."""
        return self._add(entry, deny=True)

    def remove(self, entry: str) -> bool:
        """Remove a previously added entry from both allow and deny lists."""
        entry = entry.strip().lower()
        removed = False
        for raw, domains, nets in (
            (self._raw_allow, self._allow_domains, self._allow_nets),
            (self._raw_deny, self._deny_domains, self._deny_nets),
        ):
            if entry in raw:
                raw.remove(entry)
                removed = True
                net = _as_network(entry)
                if net is not None:
                    nets[:] = [n for n in nets if n != net]
                else:
                    rule = self._parse_domain(entry)
                    domains[:] = [
                        d for d in domains
                        if not (d.host == rule.host and d.subdomains == rule.subdomains and d.apex == rule.apex)
                    ]
        return removed

    def clear(self) -> None:
        self.__init__(enforce=self.enforce, block_private=self.block_private,  # type: ignore[misc]
                      resolver=self._resolver)

    # -- querying ----------------------------------------------------------
    @property
    def is_empty(self) -> bool:
        return not (self._allow_domains or self._allow_nets)

    def entries(self) -> dict[str, list[str]]:
        return {"in_scope": list(self._raw_allow), "out_of_scope": list(self._raw_deny)}

    def _ip_in(self, target: str, nets: list[ipaddress._BaseNetwork]) -> bool:
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False
        # Canonicalise an IPv4-mapped IPv6 literal (::ffff:198.51.100.9) to its
        # embedded IPv4 so it matches IPv4 allow/deny CIDRs — otherwise a mapped
        # address silently defeats an explicit IPv4 exclusion (cross-version
        # membership is always False), the same un-mapping _ip_is_blocked does.
        addr = getattr(addr, "ipv4_mapped", None) or addr
        return any(addr in net for net in nets if net.version == addr.version)

    def evaluate(self, target: str) -> tuple[bool, str]:
        """Return ``(in_scope, reason)`` for a raw target string.

        The reason is a short human-readable explanation, useful for surfacing
        why a call was allowed or blocked.
        """

        try:
            host = normalize_target(target)
        except ValueError:
            return False, "invalid target"

        # Denials always win.
        if self._ip_in(host, self._deny_nets):
            return False, f"{host} is explicitly out of scope (IP/CIDR exclusion)"
        for rule in self._deny_domains:
            if rule.matches(host):
                return False, f"{host} is explicitly out of scope (domain exclusion)"

        # SSRF guard: private/reserved IP literals are blocked regardless of the
        # allowlist unless block_private is disabled. Hostname→IP resolution is
        # guarded separately by the tools that resolve.
        if self.block_private and is_blocked_address(host):
            return False, (
                f"{host} is a private/reserved address, blocked by MOONMCP_BLOCK_PRIVATE "
                "(set it to 0 for authorised internal-network testing)"
            )

        if not self.enforce:
            return True, "scope enforcement disabled"

        if self.is_empty:
            return False, (
                "no scope configured — add authorised targets with scope_add "
                "(or disable enforcement) before touching a host"
            )

        if self._ip_in(host, self._allow_nets):
            return True, f"{host} is in scope (IP/CIDR match)"
        for rule in self._allow_domains:
            if rule.matches(host):
                return True, f"{host} is in scope (domain match)"

        return False, f"{host} is not in the authorised scope"

    def is_in_scope(self, target: str) -> bool:
        return self.evaluate(target)[0]

    def check(self, target: str) -> str:
        """Assert *target* is in scope, returning its normalised host.

        Raises :class:`ScopeError` with an actionable message otherwise.
        """

        ok, reason = self.evaluate(target)
        if not ok:
            raise ScopeError(reason)
        return normalize_target(target)
