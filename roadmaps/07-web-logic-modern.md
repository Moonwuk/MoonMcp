# Roadmap — Layer 7: Web Logic / Modern

**Scope:** the business-logic and modern-stack probes — logic flaws, workflow
bypass, value/money manipulation, web cache deception, GraphQL (3 modules),
Fastjson deser, Client-Side Prototype Pollution. A bug here is either a probe
that completes a real financial/state-changing action, a duplicated
implementation that drifts, or a fingerprint leak.

**Modules:** `logic.py`, `workflow.py`, `value.py`, `cache_deception.py`,
`graphql.py`, `graphqli.py`, `graphqldeep.py`, `fastjson.py`, `cspp.py
(~1061 lines).

**Status as of 2026-07-27:** no fixes in this layer yet.

---

## Headline findings

**Seven HIGH** — all in the logic/value/workflow trio, all the same pattern:
a probe that completes a real financial/state-changing action with no
`dry_run`/rollback. On a live bug-bounty target these can actually place
orders, redeem coupons, escalate privileges, and confirm workflows **before
the agent gets to "confirm the side effect"**.

| ID | Module | Issue |
|---|---|---|
| WL1 | logic | `probe_race` fires N real POSTs to a state-changing endpoint — actually performs the action N times |
| WL2 | logic | `probe_mass_assignment` POSTs `role:admin`/`is_admin:true`/`balance:999999` — if vulnerable, already persisted before "verify" |
| WL3 | logic | `probe_parameter_tampering` sends `amount=-1`/`qty=0` to a live money endpoint — actually places/tampers the order |
| WL5 | workflow | `probe_workflow_skip` passes POST body through — a confirm/activate step is actually submitted cold |
| WL7 | value | `probe_coupon_reuse` applies the same code N times — actually redeems a single-use coupon N times, real financial loss |
| WL8 | value | `probe_value_tampering` sends negative/overflow to money fields — actually books the tampered value |
| WL9 | value | `probe_currency_swap` swaps currency to IDR/VND/ZWL — may actually charge in the wrong currency |

This is the clearest "detection vs exploitation" gap in the whole tool. The
docstrings say "confirm the side effect happened >1×" / "verify it persisted"
— admitting the side effect may already be done. The fix pattern is the same
as the `stack_probe` ThinkPHP fix: **add a `dry_run` flag** that either
refuses the state-changing variant, sends a no-op control first, or requires
explicit operator consent (`confirm_state_change=True`). Without it, these
probes can cause real harm on a live target.

The good news: **`fastjson.py` and `cspp.py` are correctly safe-by-design.**
Fastjson uses only `java.net.Inet4Address`/`java.net.URL` (benign DNS/HTTP
lookup, no JNDI gadget, no code execution). CSPP runs in MoonMCP's own
ephemeral browser with no engagement auth and a fresh random marker per run.
Cache deception re-reads the operator's own data. These are the models the
logic/value/workflow trio should follow.

---

## Module: `logic.py` (165 lines) — business-logic abuse

Negative-control bail, `assess_tamper` requires status+length similarity,
`scope_check` threaded through every fetch. Strengths.

**WL1 (HIGH):** `probe_race` fires N real POSTs — actually performs the
action N times. **WL2 (HIGH):** `probe_mass_assignment` POSTs privileged
fields — already persisted before "verify". **WL3 (HIGH):**
`probe_parameter_tampering` sends `amount=-1`/`qty=0` to a live money
endpoint — actually places/tampers the order. **WL4 (LOW):**
`NUMERIC_PARAM_RE` includes `id` — non-money id params tampered with
`-1`/`0x10`/`'`, producing noise.

## Module: `workflow.py` (94 lines) — multi-step flow step-skipping

`_ENFORCE_MARKERS` body-language guard avoids FPs on 2xx "complete the
previous step" pages, terminal-step severity escalation, per-step scope check
in the server wrapper. Strengths.

**WL5 (HIGH):** `probe_workflow_skip` passes `step["body"]` and
`step["method"]` through — a terminal confirm/activate step as POST is
actually submitted cold. **WL6 (MEDIUM):** `assess_step_skip` returns True
for any 2xx without enforcement markers — SPA `index.html` for every route
flags every step (FP-prone on client-routed apps).

## Module: `value.py` (149 lines) — money-field manipulation

Reuses `logic.assess_tamper` + `inject.with_param` (one implementation),
negative-control bail, `break` after one accepted payload per category.
Strengths.

**WL7 (HIGH):** `probe_coupon_reuse` applies the same coupon N times —
actually redeems a single-use coupon N times, real financial loss. **WL8
(HIGH):** `probe_value_tampering` sends `amount=-1`/`discount=101`/`price=0`
— actually books the tampered value. **WL9 (HIGH):** `probe_currency_swap`
swaps to IDR/VND/ZWL — may actually charge in the wrong currency. **WL10
(LOW):** `CURRENCY_SWAPS` includes `'` — a SQL quote mislabeled as a
currency-swap test.

## Module: `cache_deception.py` (143 lines) — web cache deception

Safe-by-design (caches and re-reads YOUR OWN data), `suppress_auth=True` on
readback, `assess_variant` requires private-like AND not-public-like
(conservative), authed-vs-anon difference guard bails when the page isn't
access-controlled. **Sound.**

**WL11 (LOW):** priming fetch doesn't check status before cookieless
readback — wasted requests on non-200 variants. **WL12 (LOW):** ~30 variants
per URL with no rate-limit/ceiling — heavy on large page lists.

## Module: `graphql.py` (99 lines) — endpoint discovery + introspection

Structural-signal check rejects pages that merely mention "GraphQL" in prose,
introspection query is read-only (`__schema`), exception-swallowed per-path.
Strengths.

**WL13 (LOW):** `COMMON_PATHS` includes `/graphiql`/`/graphql/console` UI
routes — wasteful POSTs to IDE endpoints. **WL14 (LOW):** introspection
query is shallow (`types{name kind}` only) — scope choice, not full
attack-surface pull.

## Module: `graphqli.py` (150 lines) — GraphQL NoSQLi

Server wrapper refuses `mutation`/`subscription` operations (mass-write
guard), double-send reproducibility, type-rejection filter, directional
status check. Strengths.

**WL15 (MEDIUM):** `OPERATOR_TWINS` `$in` uses hardcoded `["admin",
"administrator", "root"]` — on a query-type auth resolver (passes the
mutation guard), a match issues a real admin session token. Detection with a
real auth side effect. **WL16 (MEDIUM):** `assess_operator`/`Resp`/`_stable`
duplicate `nosqli.py` (the comment admits "mirrors nosqli.assess_operator")
— two implementations to keep in sync (drift risk).

## Module: `graphqldeep.py` (156 lines) — deeper GraphQL

All probes use read-only `{__typename}`/typo/alias queries — no mutations,
BOLA is guidance text not an automated check, `parse_batch_response` requires
≥2 results. Strengths.

**WL17 (MEDIUM):** endpoint sanity check duplicates `graphql._test_endpoint`'s
structural-signal logic — two copies of "is this GraphQL" can drift. **WL18
(LOW):** `build_batch` accepts any query string — no mutation guard at the
builder level (`deep_probe` is safe, but the function is exported).

## Module: `fastjson.py` (46 lines) — Fastjson/Jackson autoType OAST

**Safe-by-design:** all 4 payloads use `java.net.Inet4Address`/`java.net.URL`
(benign DNS/HTTP-lookup), NO JNDI gadget (`JdbcRowSetImpl`/`BasicDataSource`
absent), NO code execution. Pure builder, scope enforced in the server
wrapper. **The model the logic/value/workflow trio should follow.**

**WL19 (LOW):** nested `@type` in `fastjson-url-hashcode` exercises a
different resolve path — benign but a coverage variance. **WL20 (LOW):** no
`InetAddress` supertype payload — some Jackson configs accept base type only;
coverage gap.

## Module: `cspp.py` (89 lines) — Client-Side Prototype Pollution

**Safe-by-design:** pollution lands in MoonMCP's own ephemeral browser, server
wrapper sends NO engagement auth, fresh random marker per run, `assess` is
value-agnostic. **Sound.**

**WL21 (LOW):** 8 browser navigations per URL with no batch/ceiling — heavy
on large URL lists. **WL22 (LOW):** `hashchange_script` triggers two route
transitions in hash-router SPAs — doubles JS execution per vector.

---

## Web logic/modern layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| WL1 | logic | probe_race fires N real POSTs — actually performs the action N times | HIGH | M |
| WL2 | logic | probe_mass_assignment POSTs privileged fields — already persisted before "verify" | HIGH | M |
| WL3 | logic | probe_parameter_tampering sends amount=-1 to live money endpoint — actually places order | HIGH | M |
| WL5 | workflow | probe_workflow_skip passes POST body through — confirm/activate step submitted cold | HIGH | S |
| WL7 | value | probe_coupon_reuse applies same code N times — actually redeems single-use coupon N times | HIGH | S |
| WL8 | value | probe_value_tampering sends negative/overflow — actually books tampered value | HIGH | M |
| WL9 | value | probe_currency_swap swaps to IDR/VND/ZWL — may actually charge wrong currency | HIGH | S |
| WL15 | graphqli | $in twin uses hardcoded admin usernames — query auth resolver issues real admin token | MEDIUM | S |
| WL16 | graphqli | assess_operator/Resp/_stable duplicate nosqli.py — drift risk | MEDIUM | M |
| WL17 | graphqldeep | endpoint sanity check duplicates graphql._test_endpoint — two copies drift | MEDIUM | S |
| WL6 | workflow | assess_step_skip flags any 2xx without markers — SPA index.html FP | MEDIUM | S |
| WL4 | logic | NUMERIC_PARAM_RE includes id — non-money id params tampered, noise | LOW | S |
| WL10 | value | CURRENCY_SWAPS includes ' — SQL quote mislabeled as currency-swap | LOW | S |
| WL11 | cache_deception | priming fetch doesn't check status before readback — wasted requests | LOW | S |
| WL12 | cache_deception | ~30 variants per URL, no rate-limit/ceiling | LOW | S |
| WL13 | graphql | COMMON_PATHS includes UI routes — wasteful POSTs to IDE endpoints | LOW | S |
| WL14 | graphql | introspection query shallow — scope choice | LOW | S |
| WL18 | graphqldeep | build_batch accepts any query string — no mutation guard at builder | LOW | S |
| WL19 | fastjson | nested @type exercises different resolve path — coverage variance | LOW | S |
| WL20 | fastjson | no InetAddress supertype payload — coverage gap | LOW | S |
| WL21 | cspp | 8 browser navigations per URL, no batch/ceiling | LOW | S |
| WL22 | cspp | hashchange_script triggers two route transitions — doubles JS exec | LOW | S |

---

## Recommended next actions (this layer)

1. **WL1-WL3, WL5, WL7-WL9 (the 7 HIGHs)** — one pattern fix: add a `dry_run`
   flag to every state-changing probe. `dry_run=True` (default) either refuses
   the state-changing variant, sends a no-op control, or requires explicit
   `confirm_state_change=True`. This is the single highest-leverage fix in the
   tool — it closes 7 HIGHs with one consistent pattern. ~3-4 h total.
2. **WL15 (graphqli admin token)** — use a non-existent username in the `$in`
   twin (`nobody_${token_hex(4)}`) so a match can't issue a real admin token.
3. **WL16 + WL17 (GraphQL duplication)** — consolidate the three GraphQL
   modules into one, or factor the shared helpers (`_test_endpoint`,
   `assess_operator`) into a `graphql_common.py`.

The LOWs are polish — batch.

---

## Verification

```bash
python3 -c "from moonmcp.web import logic, workflow, value, cache_deception, graphql, graphqli, graphqldeep, fastjson, cspp; print('OK')"
python3 -m pytest tests/test_logic.py tests/test_workflow.py tests/test_value.py tests/test_cache_deception.py tests/test_graphql.py tests/test_graphqli.py tests/test_graphqldeep.py tests/test_fastjson.py tests/test_cspp.py -q
```