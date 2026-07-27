# Roadmap — Layer 10: Intel / OSINT

**Scope:** the OSINT modules — web search, CVE lookup, Shodan, OAST (config +
self-host server), 0day research, ASN, email security, page reader. A bug
here is either an open listener, a fingerprint leak, an OPSEC leak to a third
party, a prompt-injection vector, or a missing rate limit / cache.

**Modules:** `search.py`, `cve.py`, `shodan.py`, `oast.py`, `oast_server.py`,
`zeroday.py`, `asn.py`, `email.py`, `reader.py` (~1879 lines).

**Status as of 2026-07-27:** the `search.py` UA was fixed in the earlier pass
(`MoonMCP-OSINT/1.0` → browser UA). This roadmap covers what remains —
including two HIGH findings in `oast_server.py` that were missed.

---

## Headline findings

**IN1 + IN2 (both HIGH, both in `oast_server.py`):** the self-host OAST
listener defaults to `host="0.0.0.0"` — opens the catcher on **all
interfaces** with no auth. On a cloud host that exposes it to the internet; on
a laptop, the whole LAN. Worse, when `host="0.0.0.0"` and no `advertise_host`
is given, `self._advertise` falls back to `127.0.0.1` — so `base()` returns
`127.0.0.1:<port>` and the canary URLs point at loopback, **unreachable by the
target**. The default both opens the listener AND makes it non-functional;
the operator *must* set `advertise_host` explicitly or callbacks never land.
Silent misconfiguration that looks like it works.

Fix: default `host="127.0.0.1"`; require an explicit `host="0.0.0.0"` +
`advertise_host=<public-ip>` to bind publicly. One-line change + an
advertise-host assertion.

The MEDIUM cluster is OPSEC + prompt-injection:
- **IN8 (asn.py):** `ip-api.com` queried over **plain HTTP** — an on-path
  observer sees every target IP the operator researches. OPSEC leak.
- **IN5 (zeroday.py):** auto-fetched GitHub PR `.diff` injected into agent
  context — prompt-injection vector.
- **IN21 (reader.py):** fetched OSINT content not routed through
  `detect_prompt_injection` — same vector.
- **IN3 (reader.py):** no explicit UA — inherits the client default (verify
  it's the browser UA from the fix, not a tool-name string).

---

## Module: `search.py` (230 lines) — keyless web search

The 2026-07-27 UA fix is **verified present** (browser UA, no `MoonMCP-OSINT`).
Multi-engine fallback (DDG → DDG Lite → Bing), `suppress_auth=True`, offline
dork generator leaks nothing. Strengths.

**IN11 (MEDIUM):** no explicit `timeout=` on fetch — a hung engine stalls the
fallback chain. **IN18 (LOW):** static Chrome 131 UA will age into a
distinguishable fingerprint.

## Module: `cve.py` (123 lines) — NVD CVE lookup

CVSS extracted across v3.1/v3/v2, results sorted by severity, explicit
`timeout=25.0`, key optional. Strengths.

**IN6 (MEDIUM):** no NVD rate-limit/backoff — 429 returns `None`
(indistinguishable from "CVE not found"), so the agent silently treats
rate-limit as a miss. **IN13 (MEDIUM):** no caching — repeated lookups re-hit
NVD, compounding rate-limit risk.

## Module: `shodan.py` (97 lines) — host intel

Graceful paid→free fallback, IP validation, explicit timeouts. Strengths.

**IN7 (MEDIUM):** API key in URL query string (`?key={api_key}`) — Shodan
requires this, but the key can leak via http_client error strings / access
logs / redirects. Verify the client redacts query params. **IN16 (LOW):** no
rate-limit (1 req/sec keyed); no caching.

## Module: `oast.py` (140 lines) — OAST canary minting + poll

`secrets.token_hex(8)` canaries are random — **no tool name in the canary**
(verified clean). Env-driven config, defensive interaction parsing. Strengths.

**IN4 (MEDIUM):** unconfigured-state canary uses literal
`http://OAST-UNCONFIGURED/<tok>` — if an autonomous agent embeds this
placeholder in a probe sent to the target, it (a) leaks that OAST is not set
up and (b) is a recognizable fingerprint string. Fix: `generate()` should
refuse or emit a non-routable random label when unconfigured.

## Module: `oast_server.py` (135 lines) — self-host OAST HTTP listener

Stdlib-only, ring-buffer cap (`_MAX=2000`), thread-safe lock, daemon thread,
`log_message` silenced. Strengths.

**IN1 (HIGH):** default bind `0.0.0.0` — opens the listener to the network/
internet with no auth. **IN2 (HIGH):** bind 0.0.0.0 but advertises 127.0.0.1
— canaries unreachable, silent misconfiguration. **IN9 (MEDIUM):** no auth on
the listener — anyone who discovers the port can inject fake interactions,
poisoning correlation → false-positive blind-vuln confirmations. **IN19
(LOW):** plain HTTP only; no connection cap (DoS).

## Module: `zeroday.py` (726 lines) — AI-assisted 0day hunting

Rich root-cause→CWE→probe tables, incomplete-fix indicators, per-class variant
questions, `variant_search` fully offline. Strengths.

**IN5 (MEDIUM):** `cve_patch_diff` auto-fetches GitHub PR `.diff` and injects
up to 2000 chars of raw diff into agent context — prompt-injection vector.
Route through `detect_prompt_injection`. **IN10 (MEDIUM):** version-range
extraction is brittle regex on NVD prose (misclassification). **IN15
(MEDIUM):** pre-release versions treated as equal to release (semver ordering
lost) — `1.2.3-alpha` → `(1,2,3)` == `1.2.3`.

## Module: `asn.py` (126 lines) — passive IP intel

Passive (third-party only), word-boundary cloud detection, careful error-anchor
regex. Strengths.

**IN8 (MEDIUM):** `ip-api.com` over **plain HTTP** — target IPs visible to
MITM (OPSEC leak). **IN14 (MEDIUM):** no rate-limit (ip-api 45/min,
hackertarget 50/day free tiers).

## Module: `email.py` (102 lines) — email security posture

Fully passive DNS, clear issue list, A-F grading. Strengths.

**IN20 (LOW):** DKIM probing sequential (9 selectors × round-trip) — no
concurrency.

## Module: `reader.py` (200 lines) — web page reader

No external deps, scheme allowlist (http/https only), `suppress_auth=True`,
surfaces `redirect_blocked`/`blocked_reason`, parser exceptions swallowed.
Strengths.

**IN3 (MEDIUM):** no explicit `User-Agent` set — inherits the client default
(verify it's the browser UA from the fix, not a tool-name string; mirror the
`search.py` fix). **IN12 (MEDIUM):** no `timeout=` on fetch. **IN21 (MEDIUM):**
fetched content not routed through `detect_prompt_injection` — the reader is
passive but content reaches agent context.

---

## Intel/OSINT layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| IN1 | oast_server | default bind 0.0.0.0 opens listener to network/internet, no auth | HIGH | S |
| IN2 | oast_server | bind 0.0.0.0 but advertises 127.0.0.1 — canaries unreachable, silent misconfig | HIGH | S |
| IN3 | reader | no explicit UA — inherits client default (possible fingerprint leak) | MEDIUM | S |
| IN4 | oast | OAST-UNCONFIGURED placeholder canary leaks tool state if embedded | MEDIUM | S |
| IN5 | zeroday | auto-fetched PR diff injected into agent context (prompt injection) | MEDIUM | M |
| IN6 | cve | no NVD rate-limit/backoff; 429 silently looks like "CVE not found" | MEDIUM | M |
| IN7 | shodan | API key in URL query string (log/redirect leak risk) | MEDIUM | S |
| IN8 | asn | ip-api.com over plain HTTP — target IPs visible to MITM (OPSEC) | MEDIUM | S |
| IN9 | oast_server | no auth on listener — fake-callback poisoning → false-positive confirms | MEDIUM | M |
| IN10 | zeroday | version-range extraction brittle regex on NVD prose | MEDIUM | M |
| IN11 | search | no explicit timeout on fetch | MEDIUM | S |
| IN12 | reader | no explicit timeout on fetch | MEDIUM | S |
| IN13 | cve | no caching — repeated lookups re-hit NVD | MEDIUM | S |
| IN14 | asn | no rate-limit for ip-api (45/min) / hackertarget (50/day) | MEDIUM | S |
| IN15 | zeroday | pre-release versions treated as equal to release | MEDIUM | S |
| IN21 | reader | fetched content not routed through prompt-injection detection | MEDIUM | M |
| IN16 | shodan | no rate-limit (1 req/sec keyed); no caching | LOW | S |
| IN17 | __init__ | stale docstring; no __all__/re-exports | LOW | S |
| IN18 | search | static Chrome 131 UA will age into a distinguishable fingerprint | LOW | S |
| IN19 | oast_server | plain HTTP only; no TLS; no connection cap (DoS) | LOW | M |
| IN20 | email | DKIM probing sequential (9 round-trips, no concurrency) | LOW | S |

---

## Recommended next actions (this layer)

1. **IN1 + IN2 (oast_server default bind)** — one-line default change
   (`0.0.0.0` → `127.0.0.1`) + an advertise-host assertion. Kills the open-
   listener risk AND the silent non-functional default. ~15 min.
2. **IN3 (reader UA)** — mirror the `search.py` fix; verify the client default.
   ~10 min.
3. **IN4 (OAST unconfigured canary)** — `generate()` refuses or emits a non-
   routable random label. ~15 min.
4. **IN5 + IN21 (prompt injection)** — route fetched PR diffs and reader
   content through `detect_prompt_injection` before agent context.
5. **IN8 (asn plain HTTP)** — switch to HTTPS (ip-api HTTPS is paid-tier, so
   document the tradeoff or use a different provider).

The rate-limit / caching findings (IN6/IN13/IN14/IN16) are a batch — one
TTL-cache + backoff helper applied across `cve`/`shodan`/`asn`.

---

## Verification

```bash
python3 -c "from moonmcp.intel import search, cve, shodan, oast, oast_server, zeroday, asn, email, reader; print('OK')"
python3 -m pytest tests/test_oast.py tests/test_cve.py tests/test_asn.py tests/test_email.py -q
```