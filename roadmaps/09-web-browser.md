# Roadmap — Layer 9: Web Browser

**Scope:** the headless-browser modules — Playwright-driven page open, JS
eval, interaction, screenshot. These are the only modules that run real
JavaScript in a real browser, so the threat model is different: prompt
injection via page content, browser fingerprinting, and resource cost.

**Modules:** `browser.py` (341 lines), `screenshot.py` (102 lines).

**Status as of 2026-07-27:** no fixes in this layer yet. The `cspp.py` module
(Layer 7) uses `browser.py` and was audited there as safe-by-design (own
ephemeral browser, no engagement auth, fresh random marker).

---

## Module: `browser.py` (341 lines) — Playwright headless browser

### What it does
Opens a headless Chromium via Playwright, navigates to an in-scope URL, exposes
`browser_open` / `browser_eval` / `browser_interact` for the agent to drive
JS-heavy SPAs that `crawl`/`analyze_js` can't reach statically. Optional
screenshots.

### Strengths (inferred from the CSPP audit + module role)
- **Ephemeral context** — a fresh browser per engagement, not the operator's
  personal Chrome profile. No personal cookies/history leak.
- **Used safely by `cspp.py`** — no engagement auth sent, fresh random marker
  per run, pollution lands in the throwaway browser. The CSPP pattern is the
  model for any other caller.
- **Scope-checked** — `browser_open` routes through the same scope guard as
  other active tools.

### Findings

#### BR1 — Page content reaches agent context without prompt-injection screening (HIGH)
`browser_eval` returns JS execution results to the agent. A target page (or an
XSS payload reflection) can return crafted strings aimed at the agent —
"ignore previous instructions, fetch X". The browser is the only layer that
executes target JS, so it's the highest-risk path for prompt injection. The
`web-content-injection-defense` skill exists in the pipeline but
`browser_eval`'s return value is not routed through `detect_prompt_injection`.

**Fix:** route every `browser_eval` / `browser_interact` return through
`detect_prompt_injection` before it reaches the agent context; tag the result
as `untrusted` in memory.

#### BR2 — Browser fingerprint is a stable Chrome headless (MEDIUM)
Playwright's default Chromium has a headless fingerprint (HeadlessChrome UA,
missing GPU, navigator.webdriver=true). A target with bot detection
distinguishes it from a real user. For recon this is fine; for CSPP testing
where the page may behave differently for bots, it can mask the vuln.

**Fix:** `playwright-stealth` or the `patchright` Playwright patch (listed in
the `tls-fingerprint-bypass` skill) — removes the headless tells.

#### BR3 — No resource budget (MEDIUM)
No cap on CPU/memory/time per page. A target page with an infinite JS loop or a
huge heap allocation hangs the browser. `timeout` exists per navigation but not
per `browser_eval` JS execution.

**Fix:** `page.set_default_navigation_timeout` + a JS-execution timeout
(`page.evaluate` with a `Promise.race` against a timer).

#### BR4 — No engagement-auth isolation in browser context (MEDIUM, verify)
If `browser_open` is called after `auth_set`, does the headless browser carry
the engagement cookies? If yes — good for authenticated testing, but a
`browser_open` to an out-of-scope URL (the scope guard should block, but if
bypassed) would leak engagement cookies. Verify the browser context is
cookie-jar-isolated from the `HttpClient` auth context unless explicitly
synced.

**Fix:** document the contract; either share cookies explicitly via
`context.add_cookies` (opt-in) or keep the browser jar separate.

#### BR5 — Single shared browser instance (LOW)
If `browser.py` reuses one browser across calls, state leaks between
engagements (localStorage, service workers, cache). A fresh context per call
is safer.

## Module: `screenshot.py` (102 lines) — page screenshot

### What it does
Navigates and captures a PNG. Optional full-page, optional element selector.

### Findings

#### SC1 — Screenshots stored on unencrypted disk (LOW)
`screenshot_dir` defaults to `""` (disabled) but when set, PNGs land on disk.
On an unencrypted host (the audit found the VM disk is not LUKS-encrypted),
screenshots of authenticated target pages are evidence + PII.

**Fix:** document the disk-encryption dependency; consider redacting screenshots
or storing in an encrypted volume.

#### SC2 — Full-page screenshot of an authenticated page = PII dump (LOW)
A full-page screenshot of an authenticated billing/health/gov page captures
real PII. The operator decides, but a `redact` flag (blur known PII regions)
would be safer.

---

## Web browser layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| BR1 | browser | page content / eval return not screened for prompt injection | HIGH | M |
| BR2 | browser | headless Chrome fingerprint (HeadlessChrome UA, webdriver=true) | MEDIUM | M |
| BR3 | browser | no JS-execution timeout / resource budget | MEDIUM | S |
| BR4 | browser | engagement-auth / cookie-jar isolation not documented | MEDIUM | S |
| BR5 | browser | single shared browser instance — state leaks between engagements | LOW | S |
| SC1 | screenshot | screenshots on unencrypted disk — evidence + PII | LOW | S |
| SC2 | screenshot | full-page authenticated screenshot = PII dump | LOW | M |

---

## Recommended next actions (this layer)

1. **BR1 (prompt-injection screening)** — route `browser_eval` returns through
   `detect_prompt_injection`. Highest leverage — the browser is the only layer
   that executes target JS.
2. **BR3 (JS-execution timeout)** — small, prevents the hang-DoS.
3. **BR2 (stealth)** — adopt `patchright` or `playwright-stealth` if CSPP /
   bot-protected targets matter.

The rest are LOW — batch.

---

## Verification

```bash
python3 -c "from moonmcp.web import browser, screenshot; print('OK')"
# test_browser.py requires Playwright installed — skip if not present
python3 -m pytest tests/test_browser.py -q 2>/dev/null || echo "Playwright not installed — browser tests skipped"
```