# Roadmap — Layer 6: Web Protocol

**Scope:** the protocol-level probes — HTTP request smuggling, single-packet
race, WebSocket, parser differential, CRLF, HTTP methods. A bug here is either
a probe that poisons a shared connection, mutates state, destroys a resource,
or fingerprints the tool.

**Modules:** `desync.py`, `singlepacket.py`, `websocket.py`, `parserdiff.py`,
`crlf.py`, `methods.py` (~1226 lines).

**Status as of 2026-07-27:** the UA hardcodes and the `ws_probe` CRLF strip
were fixed in the earlier pass. This roadmap covers what remains.

---

## Headline findings

The 2026-07-27 fixes are **verified present**: `desync`/`singlepacket` use a
generic Chrome UA (no `MoonMCP`), `websocket` strips C0 controls from every
header field (not just `subprotocol`). Those are sound.

The remaining HIGH is **WP1 (methods.py)**: `check_methods` sends real
`PUT`/`DELETE`/`PATCH`/`CONNECT` to the **exact target URL** with no consent
gate, no intrusive gate, and no safe-path mitigation. If the server has
`DELETE` enabled, the probe *deletes the resource at the URL* — the detection
IS the destruction. `PUT` creates one. Standard safe practice is to probe a
throwaway path (`/{random}.nonexistent`) so a 2xx-on-nonexistent reveals the
method without touching real resources.

The MEDIUM cluster (WP2-WP5) is **fingerprint leaks** — four modules embed
"moon"/"Moonmcp" in canaries, markers, boundaries, JSON comments, and the
foreign Origin header. Every probe request to every target carries the tool
name. Same class of issue as the UA leak fixed in the first pass, just spread
across the protocol layer.

---

## Module: `desync.py` (308 lines) — HTTP request smuggling (detection only)

Every probe opens its own fresh socket with `Connection: close` and closes it
in `finally` — no poisoned shared connection, no victim second request. The
dual CL+TE probe sends a *complete* `0\r\n\r\n` chunked body so nothing
dangles. `interpret_modern` is pure; chunk-ext comparison correctly uses a
same-method `chunk_control` baseline. **Sound.**

**WP6 (LOW):** docstring promises `MOONMCP_ALLOW_INTRUSIVE` + scope gate but
`probe_desync`/`probe_modern_desync` enforce neither — relies on caller
discipline. **WP7 (LOW):** `_DEFAULT_UA` hardcodes Chrome/131 (late 2024);
as the version ages it becomes a stale-browser fingerprint. Overridable, but
no caller rotates it.

## Module: `singlepacket.py` (132 lines) — last-byte sync race (detection only)

Injectable `connect` for unit-testing, `n` clamped 2-40, reuses `_status_of`,
connections closed in `finally`. Strengths.

**WP2 (MEDIUM):** no consent/intrusive gate and no `scope_check` parameter;
the function fires N copies of an arbitrary caller-supplied request. By
design this performs a should-be-once action up to 40 times, so the
"detection only" docstring is misleading — the technique is inherently
state-mutating and needs an explicit gate. **WP8 (LOW):** no cleanup path if
a prime/last-byte write raises; `writer.close()` not awaited.

## Module: `websocket.py` (365 lines) — RFC 6455 handshake + CSWSH

CRLF strip applied to all header inputs (fix verified), masked client frames,
foreign Origin uses reserved `.example` TLD, echo probe is opt-in, benign
marker, `decode_frame` bounded. Strengths.

**WP3 (MEDIUM):** `_FOREIGN_ORIGIN = "https://moonmcp-cswsh-probe.example"`
— the "moonmcp" substring fingerprints the tool in target/WAF logs. Use a
neutral foreign origin. **WP9 (LOW):** echo marker `ws-probe-7f3a-echo` is a
static fingerprint if reflected/logged; randomize per call.

## Module: `parserdiff.py` (274 lines) — HTTP parser differential

Pure builders + assessors (no I/O), inert alphanumeric canaries, invalid-
controls gate out echo-everything endpoints, precedence lane is informational-
only, correct severity gradation. Strengths.

**WP4 (MEDIUM):** `CANARY = "moonpd7qz"`, `DECOY = "moondk0zx"`,
`_BOUNDARY = "----moonPD9174boundary"`, JSONC comment `// moonpd` all embed
"moon" — the tool name leaks into request bodies, query strings, Content-Type
boundaries, and JSON comments sent to every target. Use neutral random
alphanumeric strings.

## Module: `crlf.py` (67 lines) — CRLF injection / response splitting

Injects only a benign marker header/cookie, 7 payload variants incl. Unicode
CRLF and double-encoding, `scope_check` passed through, breaks on first hit.
Strengths.

**WP5 (MEDIUM):** `_MARKER_HEADER = "x-moonmcp-inj"`,
`_MARKER_COOKIE = "moonmcpcrlf"`, payload strings embed "Moonmcp" —
fingerprint in request param values and, on a successful injection, in the
forged response header itself. **WP10 (LOW):** cookie detection substring
match can false-positive. **WP11 (LOW):** `follow_redirects=False` may miss
post-redirect CRLF.

## Module: `methods.py` (50 lines) — HTTP methods + risky-method detection

Compact, passes `scope_check` through, distinguishes TRACE XST via body
reflection. **WP1 (HIGH):** sends real `PUT`/`DELETE`/`PATCH`/`CONNECT` to
the exact target URL with no consent gate, no intrusive gate, no safe-path.
`DELETE` deletes the resource; `PUT` creates one. Probe a throwaway path
(`/{random}.nonexistent`) so 2xx-on-nonexistent reveals the method without
touching real resources. **WP12 (LOW):** TRACE detection via substring
"TRACE" can false-positive on a body that legitimately contains "TRACE".

---

## Web protocol layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| WP1 | methods | Sends real DELETE/PUT/PATCH/CONNECT to exact URL — detection IS destruction | HIGH | S |
| WP2 | singlepacket | No consent/intrusive gate or scope_check; fires N real mutating requests | MEDIUM | S |
| WP3 | websocket | Foreign Origin `moonmcp-cswsh-probe.example` leaks tool name | MEDIUM | S |
| WP4 | parserdiff | Canary/decoy/boundary/JSON-comment embed "moon" — fingerprint in every probe | MEDIUM | S |
| WP5 | crlf | Marker header/cookie/payloads embed "Moonmcp" — fingerprint in requests + forged headers | MEDIUM | S |
| WP6 | desync | Docstring promises intrusive gate but functions don't enforce it | LOW | S |
| WP7 | desync | Hardcoded Chrome/131 UA ages into a stale-browser fingerprint | LOW | S |
| WP8 | singlepacket | No cleanup path if prime/last-byte write raises | LOW | S |
| WP9 | websocket | Static echo marker is a fingerprint if reflected/logged | LOW | S |
| WP10 | crlf | Cookie detection substring match can false-positive | LOW | S |
| WP11 | crlf | follow_redirects=False may miss post-redirect CRLF | LOW | S |
| WP12 | methods | TRACE detection via substring "TRACE" can false-positive | LOW | S |

---

## Recommended next actions (this layer)

1. **WP1 (methods safe-path)** — smallest HIGH, highest impact. Probe
   `/{secrets.token_hex(8)}.nonexistent` instead of the real URL. ~15 min.
2. **WP3 + WP4 + WP5 (fingerprint leaks)** — one pass: replace every
   `moon*`/`Moonmcp*` literal with neutral random strings. ~30 min total.
3. **WP2 (singlepacket consent)** — add `dry_run` + `scope_check` params,
   same pattern as the `stack_probe` ThinkPHP fix. ~30 min.

The LOWs are polish — batch.

---

## Verification

```bash
python3 -c "from moonmcp.web import desync, singlepacket, websocket, parserdiff, crlf, methods; print('OK')"
python3 -m pytest tests/test_desync_modern.py tests/test_websocket.py tests/test_parserdiff.py tests/test_crlf.py -q
```