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

## Detection tuning — the metrics pass

The eight FP/FN observations were each a **threshold** on a probe's verdict.
Tightening a threshold to kill a false positive can silently introduce a false
negative, so each was tuned only where the change is FP-suppressing *without* FN
risk, and every change ships with a **test pair** (the FP now suppressed **and** the
true positive still detected).

**Tuned (5):**
- `web/nosqli.assess_operator` — a status flip is "strong" (auth bypass) only *toward*
  success (twin reaches 2xx where the control didn't); a flip to a 4xx/5xx error is a
  weak "reached the engine" signal, not a confirmed bypass.
- `web/value.probe_currency_swap` — added the same negative-value control the sibling
  money probes use: if a garbage currency is accepted like the base, the field doesn't
  validate at all → suppress (not currency confusion).
- `web/authz.similar` — compares the **head and tail** so a large shared static shell
  (server-rendered nav) can't mask two objects that differ only in the data below the
  first 4 KiB.
- `web/authflow.scan_response_leak` — a bare code is an in-band OTP only when an
  OTP-context word sits **near** it (~60 chars), not merely somewhere in the body.
- `web/desync.interpret_modern` — the `0.CL candidate` no longer fires when the
  malformed-Expect twin was cleanly rejected with a 4xx (417 Expectation Failed is the
  RFC-compliant reply — normal, not desync).

**Left as-is — needs an app-adaptive control, not a threshold (FN risk):**
- `web/authz` sibling-sweep & multi-step chain — the honest way to suppress the
  soft-200 FP is a negative control (does a *nonexistent* id also return an object?) or
  differencing against the owner. But BOLA objects routinely share a template and
  differ only in an id substring, so any similarity/differencing threshold that kills
  the soft-200 FP also risks suppressing a **real** IDOR (demonstrated: the `_VulnApp`
  test objects are ~0.95 similar). Correctly separating "returns distinct data per id"
  (IDOR) from "returns the same body per id" (soft-200) needs per-app calibration from
  labelled real-target data — deferred rather than trade a visible FP for an invisible FN.
- `web/interp.assess_marker` — treating JSON-mandatory `\`/NUL escaping as "not
  interpretation" needs the response **content-type** plumbed into the marker check (a
  signature change to `assess_marker` + its caller), not a threshold; deferred to a
  focused change so the escaping heuristic isn't weakened blindly for non-JSON bodies.

---

*Verification method: every fixed finding above ships with a regression test that
fails before the fix and passes after. Full suite green; ruff clean.*
