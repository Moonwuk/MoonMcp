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

**Tuned via a control / plumbing (3 more, follow-up):**
- `web/interp.assess_marker` — now content-type aware: when the response is JSON, the
  JSON-mandatory escapes of the marker chars (a backslash serialised as `\\`, a NUL as its backslash-u escape
  a `` escape) are treated as transport encoding, not interpretation — so a plain JSON echo
  no longer false-fires the backslash + null-byte markers into a spurious "corroborated".
  A real strip/truncation in a JSON body is still detected; non-JSON behaviour unchanged.
- `web/authz` sibling-sweep & multi-step chain — a **negative control** replaces the
  fragile owner-differencing idea: the sweep reads a clearly-nonexistent id first; if the
  endpoint returns an object-like body for an id that can't exist AND a neighbour body is
  ~identical to it (`similar >= 0.99`), it's a soft-200 catch-all, not per-object data, so
  those neighbours are suppressed. This is FN-safe — a real endpoint returns distinct data
  per id (or 404 for the bogus id), so the `_VulnApp` IDOR still fires.
- `web/authz` multi-step chain — **collection-aware id matching** closes the residual
  same-numbered-but-unrelated FP. `extract_body_refs` now carries each exposed id's
  *collection* (the JSON field's `_id` prefix, or the href path segment), and the chain
  only injects an id into the URL's object slot when that collection is a generic
  relationship pointer (`next`/`prev`/`parent`/… or a bare `id`) or names the **same**
  collection as the slot (singular/plural-insensitive). A `product_id` pulled from an
  `/orders/<id>` response no longer chains into `/orders/<product_id>` (a same-number
  coincidence, not a chain). FN-safe: a real `order_id` / `next_id` still chains — the
  test pair asserts `301` (same collection) fires while `205` (a foreign `product_id`
  listed first, so an order-blind chain would grab it and stop) is suppressed.

---

## Precision audit — round 2 (2026-07)

A second adversarial pass aimed squarely at **detection precision** — where a probe
reaches a WRONG verdict: FP (a `confirmed`/high verdict on genuinely benign input) or
FN (a genuine signal silently dropped or downgraded below actionable). A multi-agent
sweep over the detector surface was cut short by a session limit (6 of 16 finder groups
completed, 12 candidates), so **every candidate was verified by hand against the code**
before any change. **7 fixed** (each FP+TP test pair, FN-safe) · **2 declined** (documented).

### Fixed
| Area | Defect | FP/FN |
|------|--------|-------|
| `web/authz._canon_collection` | the plural fold stripped only a single trailing `s`, so `companies`≠`company` — a real chained IDOR whenever the URL slot was an `-ies`/`-ses` plural (`/companies/`, `/categories/`, `/statuses/`) was silently dropped. Now folds `-ies→-y`, `-ses/-xes/-ches…`, then `-s`. | FN |
| `web/ssrf_meta` AWS root | `iam` matched as an unanchored substring (`Miami`/`William`) and paired with the generic `hostname` to fake the ≥2-signature gate — anchored to the IMDS listing entry `iam/`. | FP |
| `web/ssrf_meta` DigitalOcean | `interfaces`+`region` co-occur in ordinary prose — anchored both as quoted JSON keys (`"interfaces"`/`"region"`). | FP |
| `web/ssrf_meta` Azure | required `client_id`, absent from the canonical **system-assigned** MSI token body, so a genuine credential leak fell below ≥2 — now `access_token`+`token_type` (the always-present pair, matching GCP/Yandex). | FN |
| `web/ssrf_meta` k8s API-index | generic `"paths"`+`/healthz` confirmed off a reflected Swagger spec — now requires the k8s-discriminating quoted `"/apis"` array entry. | FP |
| `web/nosqli.assess_where` | `return true`/`return false` differ by one byte, so a pure echo of the posted JSON manufactured a `$where` server-side-JS oracle — payloads made equal length (`return 1==1`/`return 1==2`), mirroring `secondorder`'s discipline. | FP |
| `web/ormleak.assess_lookup` | the empty-prefix "all" (`""`) vs 17-char "none" (`CONTROL_NONE`) probes make a reflecting endpoint's body ~17 bytes longer, faking a filter differential for **every** hidden field — a reflection guard suppresses when the unlikely value is echoed (FN-safe: it matches no rows, so a real filter never surfaces it). | FP |
| `server.second_order_sqli_probe` | fed `reflected=has_error` into `confirm.evaluate`, mis-casting a SQL error as reflection corroboration, so one transient DB error at the error-seed read reached `confirmed`/high — now feeds the actual **tag reflection**; a lone error is a `likely` lead, a reflected boolean-lane hit still confirms. | FP |
| `web/crlf.assess` | the cookie marker matched as a substring, so a server that SAFELY strips the CR/LF but reflects the payload into another cookie's value raised a `confirmed` split — now matches the marker as a cookie **name** (`moonmcpcrlf=…`). | FP |
| `web/authflow` reset-link | the bare words `verify`/`confirm`/`activate`/`magic` in any URL emitted `confirmed`/high, so a benign help/docs/CDN link was a confirmed ATO — a link is `confirmed` only when token-bearing (token/otp/code param, reset/set-password path, or JWT); a bare word is a `review` lead. | FP |

### Declined — conservative by design (documented, not changed)
- `web/nosqli.assess_operator` & `web/singlepacket.assess_race` both count only **2xx** as
  "success", so a login/redemption whose success is a **3xx** redirect (PRG) is scored
  weak / `no_race_signal` rather than strong. Expanding "success" to 3xx would flag the
  opposite — *all requests redirected to an error/login* — as a hit, trading an FN for a
  new FP the tool can't distinguish without reading `Location`. The status flip is still
  surfaced (a `reason` / the status histogram), so the signal is not lost, only not
  auto-escalated. Left deliberate.

---

*Verification method: every fixed finding above ships with a regression test that
fails before the fix and passes after. Full suite green; ruff clean.*
