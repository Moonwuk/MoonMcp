# Roadmap — Layer 2: Transport

**Scope:** the networking primitives every recon/probe tool runs on. A bug
here is either a crash, a fingerprint, or an SSRF bypass.

**Modules:** `net/http.py`, `net/dns.py`, `net/tls.py`, `net/jarm.py`,
`net/ports.py`, `net/ratelimit.py` (1404 lines total).

**Status as of 2026-07-27:** the critical/high debts in this layer were fixed
in the earlier pass (see `changelog/2026-07-27-critical-and-high-debts.md`):
opt-in curl_cffi transport for browser TLS/HTTP fingerprint, DoH URL-encoding,
the raw-socket UA hardcodes. This roadmap covers what remains.

---

## Module: `net/http.py` (477 lines) — async HTTP client

### What it does
`HttpClient.fetch()` is the single outbound HTTP path for every recon and
probe tool. urllib-based by default; opt-in curl_cffi transport for browser
TLS/HTTP2 impersonation (`MOONMCP_IMPERSONATE=chrome`). Manual redirect tracing
with per-hop scope guard + credential-drop on cross-origin redirect.
Decompression-bomb guard. SSRF connect-guard on every hop.

### Function-by-function

| Function | Purpose | Verdict |
|---|---|---|
| `HttpResult` (dataclass) | structured response | strong |
| `_insecure_context / _trusted_context` | ssl contexts | OK |
| `_decode_body / _inflate` | decompress with output cap | strong (bomb guard) |
| `_blocking_fetch` | urllib transport | OK |
| `_curl_cffi_fetch` | curl_cffi transport (new) | OK, untested by suite |
| `_NoRedirect / _build_opener` | opener with only http(s) handlers | strong (no file/ftp/data) |
| `HttpClient.fetch` | main fetch loop with redirect tracing | strong, gaps below |

### Findings

#### T1 — DNS rebinding TOCTOU (HIGH, same as S1)
`fetch()` calls `self._connect_guard(host)` which resolves the host and checks
the IPs. Then `_blocking_fetch` / `_curl_cffi_fetch` resolves the host **again**
inside urllib/curl. Between the two, an attacker can flip DNS (rebinding) so
the guard sees a public IP and the connect goes to `127.0.0.1`.

**Fix:** the connect-guard returns `(reason, pinned_ip)`; `fetch` passes the
pinned IP to the transport (connect to IP, set `Host:` header = original host,
relax `check_hostname` for the IP-pin case). Standard SSRF defence.

#### T2 — `_curl_cffi_fetch` not exercised by the test suite (MEDIUM)
The new transport is opt-in via `MOONMCP_IMPERSONATE` and the env var is unset
in tests, so no test ever runs the curl_cffi branch. A regression in that
branch (header handling, redirect, body cap) would ship silently.

**Fix:** a `test_http_curl_cffi.py` that sets `MOONMCP_IMPERSONATE=chrome`
and runs the same fetch scenarios against a local server. Use `monkeypatch`
to set the env before import.

#### T3 — No connection pooling (MEDIUM)
Every request opens a fresh TCP/TLS handshake. For a 200-request recon sweep
that's 200 handshakes — slow, and a fingerprint (high handshake rate).

**Fix:** a connection pool keyed on `(scheme, host, port)`. urllib doesn't
pool natively; httpx or curl_cffi's `AsyncSession` (kept open across requests)
do. When `_USE_CURL_CFFI`, reuse one `AsyncSession` for the process lifetime.

#### T4 — `verify_tls=False` accepted per-call (LOW)
`fetch(..., verify_tls=False)` disables cert verification for that request.
Useful for self-signed dev targets, but there's no audit-log entry when it's
used. A tool could silently disable verification.

**Fix:** log a warning to `audit.jsonl` when `verify_tls=False`.

#### T5 — `max_body` default 512 KiB (LOW)
Some legitimate responses are bigger (a large sitemap, a big JSON API doc).
The cap truncates silently (`truncated=True`). Fine for recon, occasionally
surprising.

**Fix:** raise to 2 MiB, or make it per-tool (a sitemap tool passes
`max_body=8*1024*1024`).

#### T6 — Header injection via `headers` dict not sanitized (LOW)
The merge layer trusts caller-supplied `headers` dict values. The caller is
moonmcp's own tools (trusted), but a future tool that passes target-controlled
data into a header value would re-introduce CRLF. Defence-in-depth.

**Fix:** sanitize the merged dict right before the fetch, same `_strip_ctrl`
as `auth.py`.

---

## Module: `net/dns.py` (166 lines) — DNS resolution helpers

### What it does
Pure-stdlib `socket.getaddrinfo` for A/AAAA/reverse. Optional `dnspython`
for MX/NS/TXT/CNAME/SOA/CAA. DoH via `dns.google/resolve` (URL-encoded now).

### Findings

#### D1 — DoH is the only DNS-over-HTTPS, and it's hardcoded to Google (LOW)
`https://dns.google/resolve` — fine, but a privacy-conscious operator may not
want every DNS lookup to hit Google. Cloudflare (`1.1.1.1/resolve`) and Quad9
are alternatives.

**Fix:** `MOONMCP_DOH_PROVIDER=cloudflare` env var with a small provider map.

#### D2 — No DNS cache (LOW, same as S5)
Every `_resolve` / DoH call hits the network. For a redirect chain or a
subdomain sweep this is a lot of redundant lookups.

**Fix:** TTL cache (60s) keyed on `(host, rdtype)`.

#### D3 — `dnspython` import error swallowed (LOW)
`try: import dns.resolver ... except: _HAVE_DNSPYTHON = False` — any import
error (not just missing) silently disables arbitrary-record support. A
corrupt install looks like "dnspython not installed".

**Fix:** log the exception at WARNING when `_HAVE_DNSPYTHON` flips to False
on a non-`ImportError`.

---

## Module: `net/tls.py` (224 lines) — X.509 certificate inspection

### What it does
Connects with `ssl.CERT_NONE`, decodes the peer cert (DER → PEM →
`_test_decode_cert`), extracts subject/issuer/SANs/validity/serial/cipher.

### Findings

#### L1 — `_decode_der_cert` uses `ssl._ssl._test_decode_cert` (MEDIUM)
That's a private CPython API (`_ssl._test_decode_cert`). It works and is the
standard workaround for "getpeercert returns {} under CERT_NONE", but it's
private — could change across Python versions.

**Fix:** prefer `cryptography.x509.load_der_x509_certificate` when
`cryptography` is installed (it's a common dep); fall back to the private API.

#### L2 — Temp file for cert decode (LOW)
`_decode_der_cert` writes PEM to a `NamedTemporaryFile`, decodes, unlinks. I/O
for every cert inspect. Minor.

**Fix:** `cryptography` parses DER straight from bytes — no temp file.

#### L3 — No TLS version / cipher policy (LOW)
`tls_inspect` reports the negotiated version/cipher but doesn't flag weak ones
(TLS 1.0, RC4, NULL). A recon tool should say "weak" in the result.

**Fix:** a `_grade_cipher(version, cipher)` returning strong/weak/deprecated.

#### L4 — No certificate transparency / fingerprint (LOW)
CT fingerprint (SHA-256 of the cert) is a pivot for sibling-infrastructure
discovery (crtsh, censys). Not extracted.

**Fix:** `hashlib.sha256(der).hexdigest()` in the result.

---

## Module: `net/jarm.py` (321 lines) — JARM active TLS fingerprint

### What it does
A faithful async port of the Salesforce JARM algorithm: 10 crafted TLS Client
Hellos, fold the Server Hello responses into a 62-char fuzzy hash. Same JARM =
same TLS config = strong pivot for sibling infra / known stacks / C2.

### Findings

#### J1 — JARM is TLS 1.2-era; JA4 is the modern successor (LOW)
JARM (2020) is widely fingerprinted but JA4 (FoxIO, 2024) is the successor —
structured, extensible to HTTP/QUIC/SSH. Adding JA4 would keep the tool
current.

**Fix:** a `net/ja4.py` module. JA4 needs the ClientHello bytes — same socket
tap JARM already does.

#### J2 — 10 sequential TLS handshakes (LOW)
JARM fires 10 probes. Sequentially that's 10 × handshake latency. Could be
concurrent (to the same host:port) — but the server may rate-limit TLS.

**Fix:** `asyncio.gather` the 10 probes with a small concurrency cap (4).

#### J3 — No JARM database lookup (LOW)
The hash is only useful against a database (censys, sslbl). The tool reports
the hash but doesn't pivot.

**Fix:** an optional `jarm_lookup(hash)` against a public DB (rate-limited).

---

## Module: `net/ports.py` (150 lines) — async TCP connect scan

### What it does
Connect scan (full TCP handshake, unprivileged) over a port list. Bounded
concurrency.

### Findings

#### P1 — `TOP_PORTS` is a fixed 36-port list (LOW)
Recon default. For a thorough sweep a 1000-port list (nmap-style) is better.
For stealth, the top-10 is better. No way to choose.

**Fix:** `port_scan(target, profile="top36"|"top1000"|"custom")`.

#### P2 — No service banner grab beyond the connect (LOW)
`PortState.banner` exists but the grab logic isn't shown in the first 60 lines
— verify it actually sends a benign probe and reads a banner. Many services
only banner after a greeting (SMTP, FTP).

**Fix:** per-port greeting probes (`EHLO` for SMTP, `GET / HTTP/1.0` for HTTP).

#### P3 — No rate-limit integration (LOW)
The scan uses its own `asyncio.Semaphore` for concurrency but doesn't go
through `Governor` — so it doesn't count against the global rate budget. A
`port_scan` + `http_probe` interleaved can exceed RoE.

**Fix:** `await gov.__aenter__()` per connect attempt.

---

## Module: `net/ratelimit.py` (60 lines) — token bucket + concurrency gate

### What it does
`RateLimiter` (token bucket) + `Governor` (limiter + semaphore). Every
`HttpClient.fetch` enters the Governor; rate + concurrency are bounded.

### Findings

#### R1 — Token bucket not per-host (MEDIUM)
A single bucket for all outbound traffic. 10 RPS shared across 5 targets = 2
RPS per target. A bug-bounty RoE that says "10 RPS per host" is technically
violated if you test 2 hosts concurrently (20 RPS total to the same IP block).

**Fix:** per-host bucket map, each with the configured rate. Global cap as a
backstop.

#### R2 — `asyncio.Semaphore` fairness (LOW)
Python's `Semaphore` is not strictly FIFO; under contention a tool could
starve. For recon this is fine; for race-condition probes it matters.

**Fix:** a fair semaphore (asyncio Queue-based) for the probes that need
ordering. Or document that `single_packet_race` uses its own sync.

#### R3 — No metrics (LOW)
No count of how many tokens waited, how long. Hard to tune.

**Fix:** `Governor.stats()` returning `{acquired, waited, total_wait_ms}`.

---

## Layer 2 — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|---|---|---|---|---|
| T1 | http | DNS rebinding TOCTOU (shared with S1) | HIGH | M |
| T2 | http | curl_cffi branch untested | MEDIUM | S |
| T3 | http | no connection pooling | MEDIUM | M |
| R1 | ratelimit | token bucket not per-host | MEDIUM | M |
| L1 | tls | private `_ssl._test_decode_cert` API | MEDIUM | S |
| D1 | dns | DoH hardcoded to Google | LOW | S |
| D2 | dns | no DNS cache (shared with S5) | LOW | S |
| D3 | dns | dnspython import error swallowed | LOW | S |
| L2 | tls | temp file for cert decode | LOW | S |
| L3 | tls | no TLS version/cipher policy grading | LOW | S |
| L4 | tls | no cert SHA-256 fingerprint | LOW | S |
| J1 | jarm | JA4 successor not implemented | LOW | M |
| J2 | jarm | 10 sequential handshakes | LOW | S |
| J3 | jarm | no DB lookup | LOW | M |
| P1 | ports | fixed 36-port list | LOW | S |
| P2 | ports | verify banner-grab logic | LOW | S |
| P3 | ports | no Governor integration | LOW | S |
| R2 | ratelimit | semaphore fairness | LOW | S |
| R3 | ratelimit | no metrics | LOW | S |
| T4 | http | `verify_tls=False` not audited | LOW | S |
| T5 | http | 512 KiB body cap | LOW | S |
| T6 | http | merge-layer header sanitization | LOW | S |

### Recommended next actions (this layer)

1. **T1 (DNS rebinding)** — same fix as S1; do them together.
2. **T2 (curl_cffi tests)** — small, closes the "new code untested" gap.
3. **R1 (per-host rate)** — important for multi-target RoE compliance.
4. **L1 (cryptography for cert decode)** — small, removes a private-API risk.

The rest are LOW — batch into a polish pass.

---

## Verification commands

```bash
python3 -c "from moonmcp.net import http, dns, tls, jarm, ports, ratelimit; print('OK')"
python3 -m pytest tests/test_dns.py tests/test_tls.py -q
```