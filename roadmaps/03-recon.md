# Roadmap — Layer 3: Recon

**Scope:** the surface-mapping modules — passive OSINT, light active recon, and
the parsers that turn a response into structure. A bug here is either an
out-of-scope fetch (auth leaked to a third party), a DoS on the tool itself,
or a missed finding (truncation, no concurrency).

**Modules:** 24 modules under `recon/` (~3944 lines, excluding the
`config_audit.py` XML guard added 2026-07-27).

**Status as of 2026-07-27:** `config_audit.py` XML billion-laughs guard was
added in the earlier pass (see
`changelog/2026-07-27-critical-and-high-debts.md`). This roadmap covers the
rest.

The audit below was produced by a read-only pass over every recon module. The
two most common findings are:

1. **The net-layer scope gap** — `HttpClient.fetch(url, scope_check=...)`
   only applies `scope_check` to *redirect* targets, not the initial URL. Five
   modules fetch an attacker-/caller-supplied initial URL with engagement auth
   attached before any scope check runs. `sourcemaps.py` documents this gap and
   correctly re-checks the derived `map_url` — that pattern should be applied
   to the initial fetch everywhere. (This is the same root cause as the
   critical/high debt pass's `oauth_redirect_probe` SSRF fix — scope-check the
   URL *before* the first hop, not just per-redirect.)
2. **OSINT enumerators don't scope-check the apex** — `subdomains.py` and
   `wayback.py` query their OSINT providers for any apex the caller passes.
   Passive, but it enumerates assets of a domain you may not be authorized to
   research. Documented as a caller dependency, but no in-module assertion.

---

## Module: `recon/crawl.py` (131 lines) — bounded web crawler

### What it does
Fetches a page (optionally a handful of same-scope pages at depth 1) and
extracts links, forms + inputs, JS/asset URLs, query parameters, external
hosts, emails. Pure stdlib regex parsing — no headless browser.

### Findings

#### CR1 — `crawl` initial `base_url` not scope-checked (MEDIUM, same net-layer gap)
`crawl(client, base_url, ...)` fetches `base_url` with `scope_check` passed
through, but the net layer only applies it to redirects. An out-of-scope
`base_url` is fetched with engagement auth before any check.

**Fix:** `if scope_check and not scope_check(base_url): return CrawlResult(...)`
at the top of `crawl`.

#### CR2 — Depth-1 same-scope links not re-validated (LOW)
The depth-1 fetch filters `internal_links` by same-origin, but "same-origin"
is not the same as "in scope" — a same-origin link to an out-of-scope
subdomain (rare but possible with wildcard scope + exclusions) would be
fetched.

**Fix:** `scope_check(link)` before each depth-1 fetch.

#### CR3 — Regex extraction is best-effort (LOW)
`_HREF_RE`, `_FORM_RE`, `_INPUT_RE` are regex over HTML — they miss
template-generated attributes (`:href`, `v-bind:src`), SPA router links, and
broken markup. Documented limitation; `analyze_js` + `jsendpoints` cover the
SPA case.

---

## Module: `recon/config_audit.py` (534 lines) — multi-format config parser

### What it does
Detects and parses config files (XML / JSON / YAML / .env / PHP / INI / TOML /
properties) and flags secrets / credentials / sensitive keys. The XML parser
gained a size + entity + depth guard in the 2026-07-27 critical/high pass.

### Findings

#### CA1 — `_parse_yaml` uses `yaml.safe_load` (verify) (LOW)
If the YAML parser uses `yaml.load` (unsafe) anywhere, that's a code-execution
vector via `!!python/object`. The first 60 lines weren't read in this pass —
verify `safe_load` is used throughout.

#### CA2 — `.env` parser doesn't flag `PRIVATE_KEY` blocks (LOW)
Multi-line `-----BEGIN PRIVATE KEY-----` blocks are not captured by the
single-line `_GENERIC_KV_RE`. A PEM block in a `.env` is missed.

**Fix:** a dedicated PEM-block detector (`_PEM_RE` over the raw content).

---

## Recon layer — prioritized backlog (all modules)

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| RC8 | datastores | Raw-TCP probes (Redis/Memcached/MongoDB) accept host:port with no in-module scope_check — SSRF-forwarded ports reachable | HIGH | S |
| RC35 | origin | `discover_origin` resolves DNS/TLS/MX for any hostname with no scope_check — probes out-of-scope infra | HIGH | S |
| CR1 | crawl | `crawl` initial `base_url` not scope-checked (net-layer gap) | MEDIUM | S |
| RC16 | favicon | Initial `base_url` fetch not scope-checked — engagement auth leaked before favicon scope-check | MEDIUM | S |
| RC28 | jsendpoints | `analyze` initial `url` not scope-checked (net-layer gap) | MEDIUM | S |
| RC32 | openapi | `fetch_and_parse` initial `url` not scope-checked (net-layer gap) | MEDIUM | S |
| RC38 | secrets | `scan_secrets` page `url` not scope-checked before first fetch (JS loop is correctly checked) | MEDIUM | S |
| RC41 | sourcemaps | `_fetch_map` initial `url` not scope-checked (same gap the module documents for `map_url`) | MEDIUM | S |
| RC43 | subdomains | `enumerate_subdomains` does not scope-check the `domain` apex | MEDIUM | S |
| RC48 | wayback | `fetch_wayback_urls` does not scope-check `domain` | MEDIUM | S |
| RC3 | buckets | `check_buckets` unbounded `asyncio.gather` — no concurrency cap | MEDIUM | S |
| RC4 | buckets | `check_buckets` passes no timeout to fetch | MEDIUM | S |
| RC11 | depconf | `check_dependencies` sequential loop, no concurrency — 20min worst case | MEDIUM | S |
| RC12 | depconf | `scope_check` parameter accepted but never used — dead param | MEDIUM | S |
| RC21 | gitdump | `_META_FILES` fetched sequentially — 100s worst case | MEDIUM | S |
| RC9 | datastores | Raw-TCP probe total wall time up to 3×timeout — worker starvation | MEDIUM | M |
| CA1 | config_audit | verify `yaml.safe_load` (not `load`) | LOW | S |
| CA2 | config_audit | `.env` parser misses multi-line PEM blocks | LOW | S |
| CR2 | crawl | depth-1 links filtered by same-origin, not scope | LOW | S |
| CR3 | crawl | regex extraction misses SPA/template links (documented) | LOW | — |
| RC1 | binary | `analyze_bytes` joins 20000 strings before regex — spike | LOW | S |
| RC2 | binary | `_CONNSTR_RE` unbounded `1,` repeats — minor ReDoS | LOW | S |
| RC5 | buckets | `r.text(limit=300_000)` truncates large listings — dump-key missed | LOW | S |
| RC6 | content | `fetch_well_known` no Semaphore (inconsistent with `probe_paths`) | LOW | S |
| RC7 | content | `manifest.json` preview stored with no JSON validation | LOW | S |
| RC10 | datastores | `interpret_mongo_reply` second full lower-cased copy | LOW | S |
| RC13 | depconf | `detect_ecosystem` operator-precedence bug (`or`/`and`) | LOW | S |
| RC14 | deserialize | `_try_b64` no size cap on base64 decode | LOW | S |
| RC15 | deserialize | pickle protocol 0/1 markers not in `_PICKLE_PROTOS` | LOW | S |
| RC17 | favicon | `censys_query` is a static template, not computed | LOW | S |
| RC18 | fingerprint | `_TITLE_RE` with `re.DOTALL` over 200K body — slow match | LOW | S |
| RC19 | fingerprint | cookie signatures re-scan full concatenated string | LOW | S |
| RC20 | firebase | `_RTDB_URL_RE` no subdomain length validation | LOW | S |
| RC23 | gitdump | `parse_tree` off-by-one on `nul+20 > n` boundary | LOW | S |
| RC24 | headers | `_analyze_cookies` bare-flag cookie mis-parsed | LOW | S |
| RC25 | headers | `info_leaks` severity hardcoded "info" — exact-version leak is higher | LOW | S |
| RC26 | infra | `cluster_backends` dict-key on `tuple(cookies)` — unhashable raise | LOW | S |
| RC27 | infra | `ratelimit_summary` no-rate-limit concern only at ≥10 requests | LOW | S |
| RC29 | jsendpoints | `extract_endpoints` regex over uncapped text | LOW | S |
| RC30 | jslibs | hardcoded 6-library table, no refresh mechanism | LOW | M |
| RC31 | jslibs | `_v` truncates at first non-numeric chunk — `1.9` vs `1.9.0` unequal | LOW | S |
| RC33 | openapi | `_load` YAML fallback uses broad `except Exception` | LOW | S |
| RC34 | openapi | `parse_spec` no path-key traversal validation | LOW | S |
| RC36 | origin | `inspect_certificate(host, 443)` no surfaced timeout | LOW | S |
| RC37 | origin | `_ORIGIN_SUBS` hardcoded, not caller-extensible | LOW | S |
| RC39 | secrets | `_shannon_entropy` O(n × unique) via `set.count` — `Counter` cheaper | LOW | S |
| RC40 | secrets | `_redact` reveals 8 chars of a short secret | LOW | S |
| RC42 | sourcemaps | `recover_files` truncation empties content silently per-file | LOW | S |
| RC44 | subdomains | `_crtsh` 25s vs others 20s timeout | LOW | S |
| RC45 | subdomains | `_HOST_RE` accepts 63-char "TLD" | LOW | S |
| RC46 | supabase | `_jwt_role` no signature verification (detection-only, fine) | LOW | S |
| RC47 | supabase | `_SUPABASE_URL_RE` accepts 16–40 char refs (real = 20) | LOW | S |
| RC49 | wayback | empty/None `row[0]` included in urls list | LOW | S |

---

## Cross-cutting fix: the net-layer scope gap

Eight MEDIUM findings (CR1, RC16, RC28, RC32, RC38, RC41 + the
`oauth_redirect_probe` SSRF already fixed) share **one root cause**: the
initial URL of a fetch is not scope-checked; only redirects are. The cleanest
fix is **one change in `HttpClient.fetch`**: if `scope_check` is supplied,
check `url` before the first hop. That single edit closes all eight findings
at once and removes the need for every module to re-implement the check.

```python
# net/http.py, fetch(), right after computing `merged`:
if scope_check is not None and not scope_check(url):
    return HttpResult(url=url, final_url=url, status=None, reason="",
                      headers=[], body=b"", elapsed_ms=0.0,
                      error="out of scope", blocked_reason="out of scope")
```

This is the highest-leverage single fix in the recon layer.

## Cross-cutting fix: OSINT apex scope-check

`subdomains` and `wayback` should assert the apex is in scope before querying
their OSINT providers. One line each:

```python
if scope_check and not scope_check(domain):
    return {"error": "out_of_scope", "domain": domain}
```

Closes RC43 + RC48.

---

## Recommended next actions (this layer)

1. **Net-layer scope gap (one fix, closes 8 findings)** — the single
   highest-leverage edit. ~15 min + tests.
2. **RC8 + RC35 (HIGH)** — add `scope_check` to `datastores` raw-TCP probes
   and `origin.discover_origin`. ~30 min each.
3. **OSINT apex checks (RC43, RC48)** — one line each.
4. **RC3/RC4/RC11/RC21 (concurrency + timeouts)** — a small "async hygiene"
   pass: bounded `gather`, per-request timeouts.

The 33 LOWs are polish — batch them.

---

## Verification commands

```bash
python3 -c "from moonmcp.recon import crawl, gitdump, subdomains, secrets, config_audit; print('OK')"
python3 -m pytest tests/test_recon*.py tests/test_secrets*.py tests/test_gitdump*.py -q
```