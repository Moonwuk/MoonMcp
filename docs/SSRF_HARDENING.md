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

The scope gate (`_require_scope`) resolves each active tool's target **once**: it
refuses a hostname that points at a private/reserved address (so that's blocked for
**all** active tools) and stashes the validated IP in a per-call context variable
(`moonmcp/pin.py`). Pinning then closes the *rebind between the gate check and the
connect* across every direct-connection path:

- **HTTP client** (`net/http.py`) — pinned on the initial request and every redirect hop
  (its own per-hop `resolve_pin`, since a redirect can change host).
- **Port scanner** (`net/ports.py` / `port_scan`) and **datastore sweep** (`db_exposure`)
  — resolve once and connect the raw sockets by IP.
- **Raw-socket probes via the gate contextvar** — `tls_inspect` / `jarm` (cert + active
  fingerprint), the `desync` and single-packet smuggling probes, and `ws_probe` call
  `pin.connect_host(host)` before connecting, so the socket goes to the gate-validated IP.

**Safety of the contextvar**: `pin.connect_host(host)` returns the pin **only** for the
exact gated host. A tool that connects to a *different* host (candidate origins during
origin discovery, a sibling SAN, …) falls back to the hostname — the pin can never send a
connection to the wrong address. It's a `contextvars.ContextVar`, so concurrent tool calls
(each its own task context) don't see each other's pin, and every active tool overwrites
it at its own gate.

## Limits

- Behaviour is unchanged when `MOONMCP_BLOCK_PRIVATE=0` (authorised internal testing):
  the gate neither checks nor pins.
- When an outbound proxy carries an HTTP request, pinning is skipped (the proxy is the
  egress-control point); the private/reserved check still runs.
- Delegated external tools (nuclei, sqlmap, Strix) do their own resolution under their own
  network policy — out of scope for client-side pinning.
