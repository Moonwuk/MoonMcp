# Roadmap — Layer 4: Web Injection

**Scope:** the active injection probes — SQLi, NoSQLi, command/SSTI interp,
second-order SQLi, ORM leak, XXE, SSRF-to-metadata, SSRF protocol smuggling.
A bug here is either a payload that does more than detect, an SSRF in a
derived URL, or a false-positive/negative that misleads the operator.

**Modules:** `inject.py`, `nosqli.py`, `interp.py`, `secondorder.py`,
`ormleak.py`, `xxe.py`, `ssrf_meta.py`, `ssrf_protocol.py` (~781 lines).

**Status as of 2026-07-27:** no fixes in this layer yet. The
`oauth_redirect_probe` SSRF (Layer 5) shares the same root cause as WI2.

---

## Headline findings

The audit surfaced **four HIGH** issues — all of them "the probe does more
than detect". Each is a payload that, on a vulnerable target, forces the
server to make an outbound call or exfiltrate real credentials. This is the
"detection vs exploitation" line, and four probes cross it without an
explicit consent flag.

| ID | Module | Issue |
|---|---|---|
| WI1 | ssrf_meta | AWS-iam-creds probe actively extracts live cloud credentials into the probe response |
| WI2 | ssrf_meta | `scope_check` only bounds the caller's fetch, not the internal-IP URL the target is induced to fetch — false assurance |
| WI3 | ssrf_protocol | `scheme_payload` falls back to raw `http_url` as the gopher/dict/ftp host when `canary_host` is None — SSRF to arbitrary host |
| WI4 | secondorder | `oob_seed` emits a live Oracle `UTL_HTTP.REQUEST` payload the target DB executes (outbound HTTP) |

WI1 and WI4 are the clearest "weaponized beyond detection" cases. The pattern
fix is the same as the `stack_probe` ThinkPHP fix from the critical/high pass:
**add an explicit consent flag** (`confirm_creds=True`, `oob_mode=True`) and a
benign fallback (root-fingerprint first; no-op entity second). Detection
should never require the target to make an outbound call or hand over real
credentials — that's Strix's job.

WI3 is a pure SSRF: when `canary_host` is None the builder uses the raw
`http_url` as the gopher/dict/ftp host. A malformed `http_url` →
`gopher://<attacker>/_ssrf`. Fix: require `canary_host` (raise if None), or
validate it's an OAST host.

WI2 is a documentation/contract issue: `scope_check` on `probe_ssrf_metadata`
gives false assurance because it only bounds the caller's fetch of the target
URL, not the internal-IP URL the target is induced to fetch (which is
inherently out of any external scope, by design). Document this loudly; do
not let callers believe `scope_check` covers the induced request.

---

## Module: `inject.py` (34 lines) — shared param-placement helpers

Pure. `with_param` (query/body) and `inject_raw` (raw-append for CRLF).
`inject_raw` does no host/scheme validation — every caller must scope-check.
A missed caller = SSRF with raw bytes. (WI14, LOW — centralise the check or
document the contract on the function.)

## Module: `nosqli.py` (167 lines) — MongoDB operator + $where injection

Detection-only (no sleep/exfil), reproducibility gate via twin sends,
equal-length boolean twins, CONTROL baseline, explicit no-DoS contract.
Strengths. No scope guard inside the builders — correctness depends on the
`nosqli_probe` caller (WI5, MEDIUM — verify/centralise). `assess_where`
treats a length delta as proof of JS eval without strong/weak separation
(WI15, LOW). `has_session_cookie` substring-matches "token"/"sid" → fires on
benign csrf/XSRF cookies (WI16, LOW).

## Module: `interp.py` (110 lines) — Backslash-Powered-Scanner differential

Pure, multi-marker corroboration (≥2 = corroborated), never asserts a class,
self-downgrading verdicts. Strengths. `null_byte` marker sends literal `\x00`
in the URL — can trip IDS (WI17, LOW). `assess_marker` inspects only the first
occurrence of control in the body; an earlier benign echo can mask a later
transformed occurrence (WI18, LOW).

## Module: `secondorder.py` (116 lines) — second-order (stored) SQLi

UUID-tagged payloads, equal-length boolean twins, control-baseline error diff,
detection-only contract. Strengths. **`oob_seed` emits a live Oracle
`UTL_HTTP.REQUEST` payload the target DB executes** — weaponized beyond
detection (WI4, HIGH). Error lane is "high" on a single (non-reproducible)
SQL error; no reproducibility twin like the boolean lane (WI6, MEDIUM).
`normalize_reads` accepts arbitrary read-sink URLs with no in-scope check
(WI7, MEDIUM).

## Module: `ormleak.py` (85 lines) — ORM leak / relational-filter injection

Pure, reproducibility gate, empty-vs-unlikely-prefix diff (no value extracted),
per-ORM lookup forms. Strengths. Probes for `password`/`reset_token`/`api_key`/
`is_superuser` **by name** in the query string — loud IDS signature / policy-
viation flag (WI8, MEDIUM — add stealth/consent mode). `assess_lookup` compares
only (status, len); same-length different-body responses miss real leaks
(WI19, LOW).

## Module: `xxe.py` (89 lines) — blind XXE (format confusion + OAST)

Pure builders, tag sanitization, callback-only (no file read / no exfil),
None-return on non-object JSON. Strengths. `xxe_oob_payload` injects
`canary_url` verbatim as a SYSTEM entity with no scheme/host validation inside
the builder (WI9, MEDIUM — same pattern as WI3: validate the canary is an OAST
host). `_to_xml_value` recurses with no depth limit → potential RecursionError
(WI20, LOW). `_sanitize_tag` collapses distinct names to the same tag (WI21,
LOW — lossy fidelity).

## Module: `ssrf_meta.py` (98 lines) — SSRF → cloud metadata credentials

Plural-provider coverage (AWS/GCP/Azure/Alibaba/Yandex/Oracle/DO/Tencent/
Huawei), `scope_check` + timeout passed to `client.fetch`, signature-based
confirmation. Strengths. **WI1 (HIGH):** the AWS-iam-creds probe actively
extracts live cloud credentials into the probe response — no dry_run/consent
gate. Run the root-fingerprint first, creds behind an explicit
`confirm_creds=True`. **WI2 (HIGH):** `scope_check` only bounds the caller's
fetch, not the internal-IP URL the target is induced to fetch — false
assurance; document. `scan_metadata_leak` substring-matches common English
words ("hostname", "instance-id") → false-positive critical/confirmed (WI10,
MEDIUM — add structural/contextual check). 14-target fan-out with no explicit
concurrency/rate cap in this module (WI11, MEDIUM — confirm `HttpClient._gov`
bounds it). `r.text(limit=50_000) × 14` = up to 700 KB held per call (WI22,
LOW).

## Module: `ssrf_protocol.py` (82 lines) — SSRF → gopher/dict/ftp + internal-port reach

Pure helpers, closed-port control, "detection only / weaponization → Strix"
contract, per-scheme canary. Strengths. **WI3 (HIGH):** `scheme_payload` falls
back to raw `http_url` as gopher/dict/ftp host when `canary_host` is None —
SSRF to arbitrary host via gopher. Fix: require `canary_host`, validate it's
an OAST host. `assess_reachability` flags any >16-byte delta as "reachable" —
WAF/403/error pages cause false positives (WI12, MEDIUM — add status-code
awareness). `scheme_payload` uses `canary_host or http_url` with no
normalization → malformed multi-slash URLs (WI13, MEDIUM). `parse_ports` no
port-range (0–65535) or de-dup check (WI23, LOW).

---

## Web injection layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| WI1 | ssrf_meta | AWS-iam-creds probe extracts live cloud credentials — add dry_run/consent gate | HIGH | M |
| WI2 | ssrf_meta | scope_check false assurance — document the induced-request gap | HIGH | S |
| WI3 | ssrf_protocol | scheme_payload falls back to raw http_url as gopher host — SSRF to arbitrary host | HIGH | S |
| WI4 | secondorder | oob_seed emits live Oracle UTL_HTTP.REQUEST — weaponized; add dry_run/consent | HIGH | M |
| WI5 | nosqli | no scope guard inside the request builders — verify caller / centralize | MEDIUM | S |
| WI6 | secondorder | error lane "high" on a single error — add reproducibility twin | MEDIUM | S |
| WI7 | secondorder | normalize_reads accepts arbitrary read-sink URLs — no in-scope check | MEDIUM | S |
| WI8 | ormleak | probes for password/reset_token/api_key by name — loud IDS signature | MEDIUM | M |
| WI9 | xxe | xxe_oob_payload injects canary_url verbatim — no scheme/host validation | MEDIUM | S |
| WI10 | ssrf_meta | scan_metadata_leak substring-matches common English words — FP critical | MEDIUM | M |
| WI11 | ssrf_meta | 14-target fan-out — confirm HttpClient._gov bounds it | MEDIUM | S |
| WI12 | ssrf_protocol | assess_reachability flags any >16-byte delta — WAF/403 FP | MEDIUM | S |
| WI13 | ssrf_protocol | scheme_payload no normalization → malformed multi-slash URLs | MEDIUM | S |
| WI14 | inject | inject_raw no host/scheme validation — every caller must remember | LOW | S |
| WI15 | nosqli | assess_where length delta as proof of JS eval — no strong/weak | LOW | S |
| WI16 | nosqli | has_session_cookie substring-matches "token"/"sid" — FP on csrf | LOW | S |
| WI17 | interp | null_byte marker sends \x00 — can trip IDS | LOW | S |
| WI18 | interp | assess_marker inspects only first control occurrence | LOW | S |
| WI19 | ormleak | assess_lookup (status,len) only — same-length diff body missed | LOW | S |
| WI20 | xxe | _to_xml_value no depth limit — RecursionError | LOW | S |
| WI21 | xxe | _sanitize_tag collapses distinct names — lossy fidelity | LOW | S |
| WI22 | ssrf_meta | r.text(50_000) × 14 = 700 KB held per call | LOW | S |
| WI23 | ssrf_protocol | parse_ports no range/dedup check | LOW | S |
| WI24 | secondorder | make_tag 32-bit UUID suffix — collision risk (cosmetic) | LOW | S |

---

## Recommended next actions (this layer)

1. **WI3 (gopher SSRF)** — smallest HIGH. Require `canary_host`, validate it's
   an OAST host. ~15 min.
2. **WI1 + WI4 (weaponized probes)** — add consent flags + benign fallbacks,
   same pattern as the `stack_probe` ThinkPHP fix. ~1-2 h each.
3. **WI2 (scope_check documentation)** — one docstring + a return-field note.
4. **WI5/WI7/WI9 (scope gaps)** — apply the same "scope-check the initial URL"
   pattern from the recon-layer cross-cutting fix.

The MEDIUMs and LOWs are polish — batch.

---

## Verification

```bash
python3 -c "from moonmcp.web import inject, nosqli, interp, secondorder, ormleak, xxe, ssrf_meta, ssrf_protocol; print('OK')"
python3 -m pytest tests/test_sqli_lanes.py tests/test_nosqli.py tests/test_interp.py tests/test_secondorder.py tests/test_ormleak.py tests/test_xxe.py tests/test_ssrf_protocol.py -q
```