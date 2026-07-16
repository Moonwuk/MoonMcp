# Core audit — adversarial bug-hunt (2026-07)

A deep, multi-agent adversarial audit of MoonMCP's **older core** (scope / HTTP
client / config / external-tool bridges / detection probes — everything except
the freshest session code, which was hunted separately). 135 agents raised 37
findings across ~40 logic modules; each was then re-verified by hand against the
actual code before any change. This document is the honest ledger: what was
fixed, what was consciously deferred, and why.

**24 fixed** (with regression tests) · **3 deferred (architectural)** ·
**8 documented for the metrics-driven tuning pass**.

---

## Fixed

### Tool self-security
| Area | Defect | Sev |
|------|--------|-----|
| `scope.normalize_target` | a scheme-less `user@host` kept the userinfo, so the SSRF/metadata checks parsed the wrong host and a later `https://user@169.254.169.254` reached the smuggled host | high |
| `external/nuclei` + `vuln_scan` | a comma in the target smuggled extra `nuclei -u` targets past the scope guard (only the first host was validated) | high |
| `programs._load` | a hand-edited/corrupt `scope`/`scope_exclude` string was iterated per-character (dropping an intended exclusion); `null` crashed startup | medium |
| `auth.redacted` | the "safe-to-display" view masked only 3 hard-coded header names, printing a credential under any other name in cleartext | medium |
| `config._env_bool` | an empty value (`MOONMCP_BLOCK_PRIVATE=`) disabled a safety flag, while *unsetting* it kept the safe default | medium |
| `net/http._blocking_fetch` | an illegal CR/LF header value raised an uncaught `ValueError`, crashing `fetch()` instead of returning an error result | low |
| `recon/gitdump` | tree/parent object refs parsed from a (target-controlled) object skipped the 40-hex SHA validation, enabling `..`-traversal GETs outside `.git/objects/` | low |

### Detection false positives (a detection tool must not cry wolf)
| Area | Defect | Sev |
|------|--------|-----|
| `web/ssrf_meta` | a single short generic signature (`iam`, `hostname`, `region`, `access_token`) raised a CRITICAL confirmed cloud-metadata SSRF from ordinary text — now requires ≥2 | high |
| `web/exposure` | empty-signature VCS paths skipped the HTML soft-404 guard and were always confirmed, so any SPA soft-404 read as an exposed `.git` | high |
| `web/debugpanel` | the `/console` list included the generic phrase `"The console"` → any benign page flagged as a CRITICAL Werkzeug RCE | medium |
| `recon/origin` | registrable-base stripped one label whenever there were ≥2 dots, breaking multi-label suffixes (`example.co.uk` → `co.uk`) and yielding candidate hosts under the public suffix | medium |
| `web/waf` | ModSecurity fingerprinted on the generic body phrase `"not acceptable"` (HTTP 406) | low |
| `recon/config_audit` | the bind-to-all-interfaces check matched `"0.0.0.0"` as a substring, flagging a benign `10.0.0.0/8` CIDR | low |
| `knowledge/techniques` | `by_language` did a substring match (`"go"` matched `mongodb`/`django`, `"java"` matched `javascript`) — now exact | low |

### Correctness / robustness
| Area | Defect | Sev |
|------|--------|-----|
| `web/oauth` | a malformed OIDC discovery doc with a scalar where an array was expected raised `TypeError`, aborting the probe | medium |
| `findings.unique` | dedup kept the earliest-id representative, hiding a higher-severity duplicate under the lower severity | low |
| `findings.clear` | `clear(target)` matched exactly while `list(target)` matched subdomains too — asymmetric, so a cleared program left subdomain findings behind | low |
| `memory.recent` | the `kind` filter ran *after* the SQL `LIMIT`, so it returned far fewer rows than asked (or zero) when the newest rows were other kinds | low |
| `web/saml.decode_response` | `b64decode(validate=True)` rejected a line-wrapped SAMLResponse (whitespace), skipping all XSW analysis (false negative) | low |
| `web/websocket._handshake` | a single `read(4096)` could miss the `Sec-WebSocket-Accept` header when it arrived in a later TCP segment, misreporting a real WS endpoint | low |
| `web/singlepacket` | a lone open connection leaked its writer on the `< 2 connections` early return | low |
| `intel/search._real_url` | DuckDuckGo result URLs were percent-decoded twice, corrupting any destination containing a `%`-encoded reserved char | low |
| `reporting.format_markdown` | attacker-controlled evidence broke out of the blockquote and injected report structure | low |
| `obsidian.build_vault` | attacker-controlled evidence containing ``` ``` ``` broke out of the code fence and rendered as live markdown | low |

---

## Deferred — architectural (not rushed)

- **DNS-rebinding TOCTOU** (`net/ports`, and by extension `net/http`). The scope
  guard resolves a host once, but the connection re-resolves at connect time, so
  a short-TTL attacker can pass the guard with a public IP and then serve
  loopback/metadata. A correct fix is *resolve-once, connect-by-IP, pin the SNI/Host*
  applied uniformly across every connect path — a cross-cutting change to the
  networking layer that deserves its own focused PR, not a partial patch in one probe.
  **→ Addressed:** implemented as `ScopeManager.resolve_pin` + pinned HTTP(S)
  connections + `scan_ports(connect_host=…)`; see [`docs/SSRF_HARDENING.md`](SSRF_HARDENING.md).
- **Cross-origin caller-header replay on redirect** (`net/http.fetch`). Already
  bounded: a cross-origin redirect is refused unless the next hop is *in scope*, and
  the fixed sensitive set + engagement-auth keys are stripped. The residual is a
  caller-supplied header crossing between two *authorized* origins. Broadening the
  strip risks breaking auth-flow probes that legitimately follow in-scope redirects
  carrying a session — accepted as low, left deliberate.
- **Cross-process memory dedup** (`memory`). Dedup is a non-atomic SELECT-then-INSERT
  under a process-local lock; the store is single-process by default and only
  *best-effort* shared across agent processes via a common `memory.db`. This is the
  documented SQLite tradeoff, not a regression.

## Documented — detection tuning (needs the real-target metrics harness)

These are real false-positive / false-negative observations, but each is a
**threshold** on a probe's verdict. Tightening a threshold to kill a false positive
can silently introduce false negatives, and MoonMCP does not yet have the
real-target precision/recall harness (see the open metrics work) needed to measure
that trade. Blind-tuning them here would be exactly the mistake the project's own
critique warned against — so they are recorded precisely for the metrics-driven pass:

- `web/nosqli.assess_operator` — a status change *to* a 4xx/5xx error is scored as a
  "strong" injection hit (should weight a flip toward success, not toward an error).
- `web/interp.assess_marker` — JSON-mandatory escaping of `\` / NUL in a reflected
  value reads as "interpretation" (needs response content-type awareness).
- `web/value.probe_currency_swap` — no invalid-value control, so a field that accepts
  any value flags every swap as currency confusion.
- `web/authz` (3 signals) — the sibling sweep flags any ≥16-byte 2xx without
  differencing against the owner; the multi-step chain injects an extracted id into a
  fixed slot regardless of collection; `similar()` compares only the first 4 KiB, so
  two objects sharing a large static shell collapse to identical.
- `web/authflow.scan_response_leak` — a bare 4–8 digit number is reported as an
  in-band OTP whenever an OTP-context word appears anywhere in the body (no proximity).
- `web/desync.interpret_modern` — the `0.CL candidate` indicator fires on any
  Expect-handling status divergence, including the RFC-compliant 100-continue vs 417.

---

*Verification method: every fixed finding above ships with a regression test that
fails before the fix and passes after. Full suite green; ruff clean.*
