# SSRF hardening — DNS-rebinding guard (resolve-once, connect-by-IP)

## The hole

MoonMCP's SSRF guard blocks a host that resolves to a private/reserved address
(loopback, link-local `169.254.169.254`, RFC-1918, …). But the guard resolved the
name and the *connection* re-resolved it independently:

```
guard:   getaddrinfo(evil.example) -> 93.0.0.1  (public) -> allowed
connect: getaddrinfo(evil.example) -> 127.0.0.1 (rebind) -> reaches loopback
```

A target the operator put in scope but whose DNS they don't control (short TTL,
attacker-operated) could **rebind** between the check and the connect — a classic
TOCTOU — and steer an authorised probe at loopback / cloud metadata.

## The fix

Resolve **once**, then connect to **that exact IP**:

- `ScopeManager.resolve_pin(target) -> (pinned_ip, reason)` — the single resolution.
  `reason` blocks a private/reserved address; `pinned_ip` is the validated address to
  connect to. `blocked_connect_reason` is now a thin `resolve_pin(...)[1]` wrapper.
- **HTTP** (`net/http.py`): a pinned `HTTPConnection`/`HTTPSConnection` connects the
  socket to `pinned_ip` while keeping the URL hostname for the `Host` header and TLS
  **SNI + certificate verification** (the cert is checked against the hostname, not the
  IP). Applied on every hop — the initial request and each redirect.
- **Ports** (`net/ports.py`): `scan_ports(..., connect_host=<pinned_ip>)` connects every
  port to the pre-validated IP; the display name is unchanged. `port_scan` resolves once
  up front and refuses a host that resolves private.

When `MOONMCP_BLOCK_PRIVATE=0` (authorised internal testing) the guard neither checks
nor pins — behaviour is unchanged.

## Proxy caveat

If an outbound **proxy** carries the request (`HTTP(S)_PROXY` and the host isn't in
`NO_PROXY`), the socket connects to the *proxy*, not the target — so pinning the target
IP would be wrong. `_will_use_proxy(scheme, host)` detects that case and **skips pinning**,
leaving the proxy as the egress-control point. The private/reserved **reason** check still
runs in every case; only the connect-by-IP step is proxy-gated.

## Coverage

Every `@active_tool` already resolves-and-checks its target at the scope gate
(`_require_scope` → `blocked_connect_reason`), so a hostname pointing at a private
address is refused for **all** active tools. Pinning additionally closes the *rebind
between the gate check and the connect* for the direct-connection paths MoonMCP owns:

- **HTTP client** (`net/http.py`) — pinned on the initial request and every redirect hop.
- **Port scanner** (`net/ports.py` / `port_scan`) — resolves once, connects every port by IP.
- **Datastore sweep** (`db_exposure`) — the raw-TCP handshakes (Redis / Memcached / MongoDB)
  connect to the once-resolved IP; the HTTP datastore kinds pin via the HTTP client.

## Limits / next

- Other raw-socket probes (`tls_inspect` / `jarm` cert + fingerprint, the `desync` /
  single-packet smuggling probes, `ws_probe`) are **scope-gated and gate-checked** but
  still re-resolve at connect. A clean follow-up is to have `_require_scope` stash the
  pinned IP in a contextvar the low-level connect helpers read, pinning all of them at
  once instead of per-tool.
- Delegated external tools (nuclei, sqlmap, Strix) do their own resolution under their own
  network policy — out of scope for client-side pinning.
