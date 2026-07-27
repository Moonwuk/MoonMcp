# Roadmap — Layer 1: Safety Core

**Scope:** the foundational modules that every other layer depends on for
authorization, configuration, and state. A bug here is a bug everywhere.

**Modules:** `scope.py`, `config.py`, `context.py`, `auth.py`, `programs.py`
(908 lines total).

**Status as of 2026-07-27:** the critical/high debts in this layer were fixed
in the earlier pass (see `changelog/2026-07-27-critical-and-high-debts.md`):
`auth_set` CRLF sanitization, `allow_intrusive`/`rate_limit` safe defaults.
This roadmap covers what remains.

---

## Module: `scope.py` (373 lines) — authorization guardrail

### What it does
`ScopeManager` holds an in-scope allowlist and an out-of-scope denylist
(domains, IPs, CIDRs) and decides whether a target is testable. Every
packet-sending tool passes through `evaluate()` / `check()`. It also runs the
SSRF guard (`blocked_connect_reason`) that resolves a hostname and blocks it if
any resolved address is private/reserved.

### Function-by-function

| Function | Purpose | Verdict |
|---|---|---|
| `normalize_target(raw)` | Extract bare host from URL / host:port / IPv6 | OK, edge cases |
| `canonical_ip(host)` | IP object for any form incl. obfuscated IPv4 | strong |
| `_ip_is_blocked(addr)` | True if private/loopback/reserved/etc | strong |
| `is_blocked_address(host)` | IP-literal SSRF check | strong |
| `_as_network(entry)` | IP/CIDR → ip_network | OK |
| `_DomainRule.matches()` | apex + subdomain matching | OK, one gap |
| `_resolve(host)` | hostname → IPs, fail-closed on errors | strong, one gap |
| `blocked_connect_reason(target)` | connect-time SSRF guard | strong, one gap |
| `add / exclude / remove / clear` | mutate scope | OK, one hack |
| `evaluate(target)` | main (in_scope, reason) check | OK, no logging |
| `check(target)` | raise ScopeError if out of scope | OK |

### Findings

#### S1 — DNS rebinding TOCTOU (HIGH)
`blocked_connect_reason` resolves the host and checks the IPs. Then `urllib`
(or curl_cffi) resolves the host **again** at connect time. Between the two
resolutions an attacker can flip the DNS record (DNS rebinding) so the guard
sees a public IP and the connect goes to `127.0.0.1` / `169.254.169.254`.

**Fix:** pin the resolved IP. `blocked_connect_reason` returns
`(reason_or_None, resolved_ip)`. `HttpClient.fetch` connects to the resolved
IP, not the hostname (with `Host:` header = original host, `ssl.check_hostname`
relaxed for the IP-pin case). This is the standard SSRF-defence pattern
(owasp SSRF bible, the gopher-and-others tooling all do it).

#### S2 — `normalize_target` fall-through on empty host (MEDIUM)
`https:///etc/passwd` → `urlsplit` gives `host=""`, `path="/etc/passwd"`. The
code falls through with `value = parsed.path`, then tries to normalize
`/etc/passwd` as a host → nonsense. Should raise `ValueError` when `host` is
empty after `urlsplit`.

**Fix:**
```python
if "://" in value:
    parsed = urlsplit(value)
    host = parsed.hostname
    if host:
        return host.rstrip(".").lower()
    raise ValueError(f"no host in URL: {raw!r}")
```

#### S3 — `clear()` via `self.__init__()` (LOW)
`self.__init__(enforce=..., block_private=..., resolver=...)` re-runs `__init__`
on an existing instance. Works but is a hack — it relies on `__init__` being
idempotent and re-creating every field. A future `__init__` that adds a field
without resetting it leaves stale state.

**Fix:** explicit `_reset()` that clears each list, or replace the instance in
`build_context`.

#### S4 — No IDN / punycode handling (LOW)
`xn--e1afmkfd.example` (punycode) and raw Unicode domains (`straße.example`)
are not canonicalized. `urlsplit` does not decode IDN. For bug-bounty programs
with IDN targets this can cause a scope mismatch (target not recognised).

**Fix:** `idna` encoding in `normalize_target` for non-ASCII hosts.

#### S5 — No DNS cache (LOW)
`blocked_connect_reason` calls `getaddrinfo` on every invocation. A redirect
chain with 10 hops = 10 lookups. Performance, not security.

**Fix:** `lru_cache`-style cache with a short TTL (e.g. 60s) keyed on host.

#### S6 — No audit logging in `evaluate()` (LOW)
Scope decisions are not written to `audit.jsonl` from inside the scope module
—the server layer logs them at the choke point. Adding a call here would catch
any direct caller that bypasses the choke point.

**Fix:** `self._audit` callback (injectable) called with
`(tool, target, decision, reason)`.

#### S7 — `ScopeError` carries only a string (LOW)
`ScopeError(reason)` — no `target` / `rule` attributes. Programmatic callers
can't inspect why. Minor.

**Fix:** `ScopeError(reason, *, target=None, rule=None)`.

#### S8 — No "apex only, no subdomains" mode (LOW)
`example.com` → apex + subdomains. `*.example.com` → subdomains only. There is
no syntax for "apex only". Real programs occasionally want this. Minor.

**Fix:** a third rule form, e.g. `=example.com` (sigil prefix) for apex-only.

---

## Module: `config.py` (137 lines) — runtime settings

### What it does
`Settings` frozen dataclass + `load_settings()` that builds it from env vars.
The single source of truth for enforce_scope, block_private, allow_intrusive,
rate_limit, timeout, user_agent, redirects, API keys.

### Function-by-function

| Function | Purpose | Verdict |
|---|---|---|
| `Settings` (dataclass) | immutable config snapshot | strong |
| `_env_bool / _env_float / _env_int / _env_list` | env var parsers | OK |
| `load_settings()` | env → Settings | OK |

### Findings

#### C1 — No config-file support (MEDIUM)
Only env vars. For a 169-tool server, env-only config is brittle (long
`moonmcp-launch.sh` default block, `opencode.jsonc` env map). A
`MOONMCP_CONFIG=/path/to/config.toml` would let an operator keep all settings
in one versioned file.

**Fix:** add `tomllib` (stdlib 3.11+) loader; env vars still override file
values.

#### C2 — No validation of `user_agent` / `impersonate` interaction (LOW)
`MOONMCP_IMPERSONATE=chrome` makes curl_cffi supply its own UA. `MOONMCP_USER_AGENT`
is still set. The two can contradict (curl_cffi's Chrome 131 UA vs the env's
Chrome 131 UA — probably fine; vs a custom "research-bot" UA — the impersonated
fingerprint says Chrome but the UA says bot, which is a tell).

**Fix:** when `_USE_CURL_CFFI`, ignore `MOONMCP_USER_AGENT` unless explicitly
flagged (`MOONMCP_OVERRIDE_IMPERSONATE_UA=1`).

#### C3 — No reload (LOW)
`load_settings()` runs once at startup. Changing a setting requires a restart.
For long-running engagements this is fine; for interactive tuning it's rigid.

**Fix:** `Settings.reload()` + a signal handler (SIGHUP) — optional.

#### C4 — `external_timeout: float = 300.0` is huge (LOW)
5 minutes for a single CLI invocation. A hung nuclei scan can block the
governor slot for that long. 120s is safer.

---

## Module: `context.py` (107 lines) — application wiring

### What it does
`build_context()` constructs the whole `AppContext` (settings, scope, governor,
http, findings, auth, oast, snapshots, audit, programs, history, memory) and
wires the active program's scope + the auth/program header merge into the
`HttpClient`.

### Function-by-function

| Function | Purpose | Verdict |
|---|---|---|
| `AppContext` (dataclass) | holds every subsystem | OK |
| `build_context(settings)` | construct + wire everything | OK, one gap |
| `to_dict(obj)` | recursive dataclass → JSON | strong |

### Findings

#### X1 — Active-program scope applied without de-dup (LOW)
`build_context` does `scope.add(entry)` for every active-program scope entry on
top of the env-var scope. If the same host is in both, it's added twice. The
`add` dedups the raw list, but `_DomainRule` / `_allow_nets` get duplicate
entries. Harmless (just slower matching) but sloppy.

**Fix:** `scope.clear()` before applying the active program, or check
`entry in scope.entries()["in_scope"]` first.

#### X2 — No teardown (LOW)
`build_context` starts the OAST server, opens `memory.db`, etc. There is no
`teardown()` to close them cleanly. On process exit the OS cleans up, but a
graceful shutdown for tests / REPL would be nicer.

**Fix:** `AppContext.close()` that stops the OAST listener, closes the SQLite
handle, flushes the audit log.

#### X3 — `oast_server` field is `None` at construction (LOW)
`AppContext.oast_server: CallbackServer | None = None` — the field exists but
`build_context` never sets it. The OAST server is started lazily by
`oast_selfhost`. A reader of the dataclass thinks it's always present. Minor
naming/contract issue.

**Fix:** either construct it lazily inside `oast_selfhost` and store on the
context (already the pattern), or document the field as "set lazily".

---

## Module: `auth.py` (105 lines) — engagement auth context

### What it does
`AuthContext` holds the custom headers / cookies / bearer / basic for the
current engagement and merges them into every in-scope request.

### Function-by-function

| Function | Purpose | Verdict |
|---|---|---|
| `_sanitize_header_value / _sanitize_header_name` | strip C0 controls | strong (added 2026-07-27) |
| `set_bearer / set_basic / set_cookie_string / update_headers` | entry points | strong (sanitized) |
| `merged_headers()` | headers + Cookie header | OK |
| `clear / is_set / redacted` | lifecycle + safe display | OK |

### Findings

#### A1 — `merged_headers` does not sanitize again (LOW, defence-in-depth)
The entry points sanitize, but `merged_headers` just joins. If a future code
path writes to `self.cookies` / `self.headers` directly (bypassing the setters),
the merge re-introduces the CRLF. Defence-in-depth: sanitize at the merge too.

**Fix:** `_sanitize_header_value(v)` in the `merged_headers` loop.

#### A2 — Cookie value can still contain `;` (LOW)
`set_cookie_string` splits on `;`, so a value with `;` would split into a
bogus extra cookie. Real cookie values can contain `;` inside quotes
(`session="a;b"`). Edge case.

**Fix:** parse with `http.cookies.SimpleCookie` instead of `split(";")`.

#### A3 — No expiry / refresh hook (LOW)
Tokens expire. There's no `refresh_callback` for an OAuth flow that needs a
silent refresh mid-engagement. The operator must re-`auth_set` manually.

---

## Module: `programs.py` (186 lines) — engagement profiles

### What it does
`Program` bundles a name + scope + bug-bounty header + optional UA + note.
`ProgramStore` holds them, persists to `programs.json`, tracks the active one.
The active program's headers + UA are merged into every in-scope request.

### Function-by-function

| Function | Purpose | Verdict |
|---|---|---|
| `parse_header(spec)` | "Name: value" → (name, value) | OK |
| `Program.headers()` | header dict the program contributes | OK |
| `Program.summary()` | JSON-friendly overview | OK |
| `ProgramStore._load / _save` | persistence | OK, one gap |
| `ProgramStore.add / remove / use / get / list` | mutation | OK |
| `active_headers()` | headers contributed by the active program | OK |

### Findings

#### P1 — `programs.json` mode is 0644 (MEDIUM)
The file holds researcher handles, Standoff UUID tokens, and scope. It's
world-readable on a shared host. Should be 0600.

**Fix:** `os.chmod(path, 0o600)` after writing in `_save`; `umask`-aware
`open(path, "w", 0o600)`.

#### P2 — No schema versioning (LOW)
`_load` does `Program(**{k: raw[k] for k in raw if k in fields})` — forward-
compatible (ignores unknown fields), but no version field. A future schema
change that renames a field silently drops data.

**Fix:** `"version": 1` in the saved dict; `_load` warns / migrates on mismatch.

#### P3 — `parse_header` allows empty value (LOW)
`"X-Bug-Bounty: "` → `("X-Bug-Bounty", "")`. An empty header value is legal
HTTP but probably a mistake. Worth a warning.

#### P4 — Active program not validated on load (LOW)
If `programs.json` says `active: "stale-program"` but that program was
removed, `_load` checks `if active in self._programs` — good. But it does not
clear `active` if the program is gone on a future edit. Minor.

---

## Layer 1 — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|---|---|---|---|---|
| S1 | scope | DNS rebinding TOCTOU — pin resolved IP | HIGH | M |
| P1 | programs | `programs.json` mode 0644 → 0600 | MEDIUM | S |
| S2 | scope | `normalize_target` empty-host fall-through | MEDIUM | S |
| C1 | config | no config-file support (toml) | MEDIUM | M |
| X2 | context | no `teardown()` for graceful shutdown | LOW | S |
| A1 | auth | `merged_headers` no defence-in-depth sanitize | LOW | S |
| A2 | auth | cookie `;` inside quotes | LOW | S |
| S3 | scope | `clear()` via `self.__init__()` | LOW | S |
| S4 | scope | no IDN/punycode handling | LOW | S |
| S5 | scope | no DNS cache | LOW | S |
| S6 | scope | no audit logging in `evaluate` | LOW | S |
| S7 | scope | `ScopeError` no structured attrs | LOW | S |
| S8 | scope | no apex-only mode | LOW | S |
| C2 | config | UA / impersonate interaction | LOW | S |
| C3 | config | no reload | LOW | M |
| C4 | config | `external_timeout` 300s | LOW | S |
| X1 | context | active-program scope not de-duped | LOW | S |
| X3 | context | `oast_server` field contract | LOW | S |
| P2 | programs | no schema versioning | LOW | S |
| P3 | programs | `parse_header` allows empty value | LOW | S |
| P4 | programs | stale `active` not cleared | LOW | S |
| A3 | auth | no token refresh hook | LOW | M |

**Severity:** HIGH = security bug / SSRF bypass. MEDIUM = correctness or
hygiene. LOW = polish.
**Effort:** S = <30 min, M = 1-4 h, L = >4 h.

### Recommended next actions (this layer)

1. **S1 (DNS rebinding)** — the only HIGH. Worth doing. Pattern: guard returns
   `(reason, pinned_ip)`, fetch connects to the IP. ~2-3h with tests.
2. **P1 (programs.json 0600)** — one-liner, do it now.
3. **S2 (normalize_target)** — small, do it alongside S1.

The rest are LOW — batch them into a "polish" pass when the mood strikes.

---

## Verification commands

```bash
# All Layer-1 modules import cleanly
python3 -c "from moonmcp import scope, config, context, auth, programs; print('OK')"

# Existing scope/auth tests pass
python3 -m pytest tests/test_scope.py tests/test_programs.py -q
```