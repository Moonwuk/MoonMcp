# Roadmap — Layer 5: Web Auth

**Scope:** the authentication/authorization attack modules — OAuth
redirect_uri bypass, SAML XSW, JWT jku/x5u, BOLA/IDOR diff, auth-flow ATO.
A bug here is either an XML DoS on attacker-supplied input, an SSRF in a
JWT header URL, or a false-positive/negative that misleads the operator.

**Modules:** `oauth.py`, `saml.py`, `jwt.py`, `authz.py`, `authflow.py`
(~810 lines).

**Status as of 2026-07-27:** the `oauth_redirect_probe` SSRF was fixed in the
critical/high pass (scope-check `authorization_endpoint` before fetch). This
roadmap covers what remains.

---

## Headline finding

**WA4 (HIGH): `saml.py` uses `xml.etree.ElementTree.fromstring` with no
entity-expansion guard.** stdlib `ET` is vulnerable to billion-laughs /
quadratic entity expansion by default (CVE-2013-1664-class). A SAMLResponse is
*attacker-supplied input from the target*; a malicious payload with
`<!DOCTYPE x [<!ENTITY a "...&a;&a;...">]>` can cause CPU/memory exhaustion in
the MoonMCP process.

This is the **same class of bug** as the `analyze_config` XML billion-laughs
fixed in the critical/high pass — but `saml.py` was missed because it's in the
`web/` layer, not `recon/`. The fix is identical: switch to
`defusedxml.ElementTree.fromstring` (or pre-strip `<!DOCTYPE` + cap
`xml_text` length at the entry points).

WA4 is the only HIGH in this layer. The rest are MEDIUM/LOW.

---

## Module: `oauth.py` (183 lines) — OIDC discovery + redirect_uri bypass

The 2026-07-27 SSRF fix is **verified present** — `probe_redirect_uri_bypass`
hard-gates `authorization_endpoint` via `scope_check(ep)` before any fetch.
Strengths: redirects disabled, canary never contacted, 5 redirect_uri
variants.

**WA1 (LOW):** `scope_check` is `Optional` and defaults to `None` — the fix
is opt-in, not enforced at the signature. A future caller that forgets to
pass it reopens the SSRF. Make it mandatory, or assert non-None at entry.
**WA2 (LOW):** only 5 `redirect_uri` variants; misses `javascript:`, CRLF,
double-`@` — weak negative signal. **WA3 (LOW):** no `client_id` fallback →
early IdP rejection → false negatives.

## Module: `saml.py` (240 lines) — SAML XSW (signature wrapping)

Pure functions (no network in-module), XSW coverage is 3 representative
topologies, `assess_variant` requires the forged marker to appear in
`variant_body` but not in `accepted_body`/`corrupted_body` — strong
differential logic. Strengths.

**WA4 (HIGH):** `ET.fromstring` with no entity guard — billion-laughs DoS on
attacker-supplied SAMLResponse. **WA5 (MEDIUM):** `decode_response` base64-
decodes with no input/decoded size cap — amplifies the DoS. **WA6 (MEDIUM):**
`build_variant` `copy.deepcopy` on unbounded parsed tree — unbounded memory.
**WA7 (LOW):** repeated re-parse of `xml_text` across functions — wasteful.

The WA4+WA5+WA6 fix is one dependency (`defusedxml`) + 3 entry-point guards
(cap `xml_text` length, cap decoded size).

## Module: `jwt.py` (196 lines) — JWT decode + weakness triage

All forge/crack functions are pure and offline; `analyze_jwt` flags
`jku`/`x5u`/`kid` as key-injection surface; `crack_hmac_secret` uses
`hmac.compare_digest` (constant-time). Strengths.

**WA8 (MEDIUM):** `forge_remote_key_header` injects an arbitrary `url` into
the `jku`/`x5u` header with no validation. Safe today (the only caller
`jwt_jku_probe` passes an OAST canary URL), but no invariant guard — a future
caller passing user input would mint a token that instructs the target to
fetch an attacker URL (SSRF-via-target). Fix: assert the URL is an OAST canary
or document the invariant loudly. **WA9 (LOW):** `forge_alg_confusion` takes
`public_key: str` with no PEM validation. **WA10 (LOW):** 2-segment token
accepted as valid; should map to `alg:none` family directly. **WA11 (LOW):**
default `WEAK_JWT_SECRETS` only ~26 entries — weak negative.

## Module: `authz.py` (190 lines) — BOLA/IDOR multi-step chains

GET-only (no mutation), `SequenceMatcher` ≥0.95 threshold for `direct_bola`
(low FP), `scope_check` threaded into every fetch, `suppress_auth=True` drops
owner creds for cross-identity probes. Strengths.

**WA12 (MEDIUM):** multi-step chain swaps only `ref0`; multi-segment object
refs (`/org/X/user/Y`) not fully walked — chained IDOR into the other slot
is missed. **WA13 (MEDIUM):** `similar` compares first 4 KiB only → FN for
large objects, weak FP guard for paginated lists. **WA14 (LOW):**
`sibling_values` walks only `(n±1,1,2,0)` — sparse/non-sequential ids missed.
**WA15 (LOW):** sibling sweep runs anon-only when `b_headers` None —
edge-rejecting servers yield zero signal.

## Module: `authflow.py` (209 lines) — ATO flow abuses

Pure scanner, `_redact` masks secrets before logging, excludes csrf/oauth
`access_token` from "leak" set (avoids FPs), reset-poison probe only poisons
the header (connection still targets the real in-scope host). Strengths.

**WA16 (MEDIUM):** `probe_reset_poison` doesn't enforce OAST canary; a
non-OAST reflected string can FP at HIGH verdict. **WA17 (MEDIUM):** bare
4-8 digit code branch fires on OTP-context prose + any digit run (years,
phone, status) → noisy MEDIUM. **WA18 (LOW):** `_LINK_RE` matches `code=`/
`token=` without validating value shape → FP at HIGH. **WA19 (LOW):**
`probe_response_leak` single static request; "confirmed" verdict overstates
unvalidated hit.

---

## Web auth layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| WA4 | saml | ET.fromstring no entity guard — billion-laughs DoS on SAMLResponse | HIGH | S |
| WA5 | saml | decode_response no size cap — amplifies DoS | MEDIUM | S |
| WA6 | saml | build_variant deepcopy on unbounded tree — unbounded memory | MEDIUM | S |
| WA8 | jwt | forge_remote_key_header accepts arbitrary url — no invariant guard | MEDIUM | S |
| WA12 | authz | multi-step chain swaps only ref0 — multi-segment refs missed | MEDIUM | M |
| WA13 | authz | similar compares first 4 KiB only — FN for large objects | MEDIUM | S |
| WA16 | authflow | probe_reset_poison doesn't enforce OAST canary — FP at HIGH | MEDIUM | S |
| WA17 | authflow | bare 4-8 digit code branch fires on OTP prose + any digit — noisy | MEDIUM | S |
| WA1 | oauth | scope_check Optional/defaults None — fix is opt-in, not enforced | LOW | S |
| WA2 | oauth | only 5 redirect_uri variants — weak negative | LOW | S |
| WA3 | oauth | no client_id fallback — false negatives | LOW | S |
| WA7 | saml | repeated re-parse of xml_text — wasteful | LOW | S |
| WA9 | jwt | forge_alg_confusion no PEM validation — footgun | LOW | S |
| WA10 | jwt | 2-segment token accepted as valid — should be alg:none family | LOW | S |
| WA11 | jwt | default WEAK_JWT_SECRETS ~26 entries — weak negative | LOW | S |
| WA14 | authz | sibling_values walks only (n±1,1,2,0) — sparse ids missed | LOW | S |
| WA15 | authz | sibling sweep anon-only when b_headers None — zero signal | LOW | S |
| WA18 | authflow | _LINK_RE matches code= without validating value shape — FP | LOW | S |
| WA19 | authflow | probe_response_leak single static request — "confirmed" overstates | LOW | S |

---

## Recommended next actions (this layer)

1. **WA4 + WA5 + WA6 (SAML XML DoS)** — one fix: `defusedxml.ElementTree` +
   size caps at `decode_response` / `parse_structure` entry. ~30 min. This is
   the same fix pattern as the `analyze_config` billion-laughs from the
   critical/high pass, just applied to a layer that was missed.
2. **WA8 (JWT jku/x5u invariant)** — assert the URL is an OAST canary in
   `forge_remote_key_header`. ~15 min.
3. **WA16 + WA17 (authflow FPs)** — enforce OAST canary; tighten the bare-code
   regex. ~30 min.

The rest are LOW — batch.

---

## Verification

```bash
python3 -c "from moonmcp.web import oauth, saml, jwt, authz, authflow; print('OK')"
python3 -m pytest tests/test_oauth.py tests/test_saml.py tests/test_authz.py -q
```