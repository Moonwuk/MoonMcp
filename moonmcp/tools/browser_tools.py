"""Browser-driven tools (Playwright + Chromium).

Extracted from server.py. Rendered screenshots, a headless open (HTML / console /
network capture), client-side prototype-pollution probing, in-page JS evaluation
and scripted interaction. The shared `_browser_auth` helper (injects the session
auth header + cookies into the browser context) moves with them. Importing this
module registers the tools on the shared `mcp` instance.
"""

from __future__ import annotations

import secrets

from .. import confirm as confirmmod
from ..context import to_dict
from ..mcp_core import _resolve_block, _scope_check, active_tool, get_context, mcp
from ..web import browser as browsermod
from ..web import cspp as csppmod
from ..web import screenshot as screenshotmod


@mcp.tool()
@active_tool()
async def screenshot(target: str, full_page: bool = True, return_base64: bool = False) -> dict:
    """Capture a rendered screenshot of an in-scope page using Playwright +
    Chromium, saved to disk (path returned). Optional and self-degrading: if
    Playwright/Chromium isn't installed, returns a clear note with an install
    hint instead of erroring. Set return_base64 to also inline the PNG. In scope only.
    """

    import tempfile

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    out_dir = ctx.settings.screenshot_dir or __import__("os").path.join(
        tempfile.gettempdir(), "moonmcp-screenshots"
    )
    result = await screenshotmod.capture(
        url, out_dir=out_dir, full_page=full_page, return_base64=return_base64,
        timeout_ms=int(ctx.settings.timeout * 2000),
    )
    return to_dict(result)


def _browser_auth(url: str) -> tuple[dict, list[dict]]:
    """Build (extra_headers, cookies) for the headless browser from the engagement
    auth context, so it drives the target authenticated."""

    ctx = get_context()
    headers = dict(ctx.auth.headers)  # raw headers (Cookie goes via the jar)
    cookies = [{"name": k, "value": v, "url": url} for k, v in ctx.auth.cookies.items()]
    return headers, cookies


@mcp.tool()
@active_tool()
async def browser_open(target: str, capture_html: bool = False,
                       wait_until: str = "load") -> dict:
    """Open an in-scope URL in a headless browser (Playwright + Chromium) and
    return what a real browser sees after JavaScript runs: final URL, status,
    title, the rendered page **text** (and HTML if `capture_html`), plus the
    **console log**, the **network requests** the page made, and any page errors.
    Ideal for JS-heavy SPAs (endpoint/secret discovery) where a raw HTTP fetch
    sees almost nothing. Uses the engagement auth (`auth_set`) so the app is
    driven authenticated. Optional/self-degrading if Playwright is absent.
    `wait_until`: load | domcontentloaded | networkidle. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    headers, cookies = _browser_auth(url)
    result = await browsermod.browse(
        url, capture_html=capture_html, wait_until=wait_until,
        extra_headers=headers, cookies=cookies, scope_ok=_scope_check(),
        resolve_block=_resolve_block(),
    )
    return to_dict(result)


@mcp.tool()
@active_tool()
async def cspp_probe(target: str, wait_until: str = "networkidle") -> dict:
    """**Client-side prototype pollution** — headless-browser detection, safe by design.
    SPAs that parse `location.search`/`location.hash` and deep-merge them can let a
    `__proto__`/`constructor.prototype` URL path write `Object.prototype` in the page's
    JS (the client-side root of DOM-XSS gadget chains). This loads each candidate URL in
    MoonMCP's **own ephemeral browser**, then reads `Object.prototype[<marker>]` back —
    the pollution lands in our throwaway Chromium, **never on the target server** (we send
    an ordinary GET the server ignores) and we send **no engagement auth** (the sink fires
    regardless of login, so nothing leaks). The marker is a fresh random key per run that a
    clean baseline proves absent, so any read-back under a payload is attributable. Tries
    `__proto__`/`constructor` bracket+dotted paths in both query and hash (firing
    `hashchange` for hash-router sinks). Detection-only — proving the sink is reachable, not
    a working XSS; gadget→XSS chaining → Strix. Needs Playwright/Chromium (self-degrades if
    absent). In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    marker = csppmod.MARKER_PREFIX + secrets.token_hex(4)
    read = csppmod.read_script(marker)
    scope_ok = _scope_check()

    async def _read(u, script):
        # No engagement auth on purpose (nothing to leak); scope-gated navigations.
        return await browsermod.browse(u, script=script, capture_text=False,
                                       wait_until=wait_until, scope_ok=scope_ok,
                                       resolve_block=_resolve_block())

    baseline = await _read(url, read)
    if not baseline.available:
        return {"target": url, "available": False, "error": baseline.error,
                "install_hint": baseline.install_hint}
    if baseline.error or baseline.eval_error:
        return {"target": url, "available": True, "verdict": "inconclusive",
                "confidence": "low", "vectors": [],
                "error": baseline.error or baseline.eval_error,
                "note": "could not establish a clean prototype baseline (navigation/eval "
                        "failed) — re-run against a reachable page that returns HTML"}

    hits: list[dict] = []
    for label, vurl, is_hash in csppmod.vectors(url, marker):
        script = csppmod.hashchange_script(marker) if is_hash else read
        r = await _read(vurl, script)
        if csppmod.assess(baseline.eval_result, r.eval_result):
            hits.append({"vector": label, "url": vurl, "value": r.eval_result})

    verdict = confirmmod.evaluate(
        injection_hits=[f"prototype-pollution/client-side ({h['vector']})" for h in hits],
        reflected=bool(hits))
    return {"target": url, "available": True, **verdict,
            "polluted_property": marker if hits else None,
            "vectors": hits, "baseline_marker": baseline.eval_result,
            "note": ("client-side prototype pollution — the page's JS merged a URL "
                     "__proto__/constructor path into Object.prototype (in our own ephemeral "
                     "browser only; the target server is untouched). Locating a gadget → XSS → Strix"
                     if hits else
                     "no client-side prototype-pollution sink reached via URL query/hash "
                     "(the page may pollute from a different source or on a later event)")}


@mcp.tool()
@active_tool()
async def browser_eval(target: str, script: str, wait_until: str = "load") -> dict:
    """Run JavaScript in the page's context — the **browser console** — against an
    in-scope URL and return the (JSON-serialisable) result, plus the console log
    and any page errors. Use it to inspect the live DOM, read `window`/JS state,
    extract data a SPA rendered, or check a JS value. `script` is a JS expression
    (e.g. `document.title`, `Object.keys(window)`, `[...document.querySelectorAll('a')].map(a=>a.href)`).
    Uses the engagement auth. Authorised testing only; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    headers, cookies = _browser_auth(url)
    result = await browsermod.browse(
        url, script=script, capture_text=False, wait_until=wait_until,
        extra_headers=headers, cookies=cookies, scope_ok=_scope_check(),
        resolve_block=_resolve_block(),
    )
    out = to_dict(result)
    # trim the network/text noise — browser_eval is about the script result
    out.pop("html", None)
    out.pop("text", None)
    return out


@mcp.tool()
@active_tool()
async def browser_interact(target: str, actions: list[dict]) -> dict:
    """Drive the headless browser through a sequence of ACTIONS against an in-scope
    URL — click, fill/type inputs, submit forms, wait for selectors, run JS — to
    walk a real user flow (login, multi-step form, SPA navigation). Returns the
    resulting page state (final URL, title, text), per-step results, plus the
    console log, network requests, page errors, **cookies and localStorage**.

    `actions` is a list of dicts, e.g.
    `[{"action":"fill","selector":"#user","value":"a"},
      {"action":"fill","selector":"#pass","value":"b"},
      {"action":"click","selector":"#login"},
      {"action":"wait_for","selector":".dashboard"},
      {"action":"eval","script":"localStorage.getItem('token')"}]`.
    Supported: click, fill, type, press, wait_for, wait, goto (scope-checked),
    eval. Uses the engagement auth. Authorised testing only; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    headers, cookies = _browser_auth(url)
    result = await browsermod.interact(
        url, actions or [], extra_headers=headers, cookies=cookies,
        scope_ok=_scope_check(), resolve_block=_resolve_block(),
    )
    return to_dict(result)
