"""Client-side prototype pollution (CSPP) — headless-browser detection, safe by design.

Many SPAs parse ``location.search`` / ``location.hash`` (jQuery `$.parseParams`,
hand-rolled query mergers, router param objects) and deep-merge the result into an
object. A ``__proto__`` / ``constructor.prototype`` path in the URL then writes
``Object.prototype`` **in the page's own JS realm** — the client-side root of
DOM-XSS gadget chains (PortSwigger client-side PP research; the source of many
gadget→XSS bounties).

Detection loads each candidate URL in MoonMCP's **own ephemeral headless browser**
and reads ``Object.prototype[<marker>]`` back. Crucially this is *safe by design*:
the pollution lands in our throwaway Chromium context, **never on the target server**
(the query/hash we send is an ordinary GET the server almost always ignores), and
the probe sends **no engagement auth** (a client-side sink fires regardless of login,
so there is nothing to leak). The ``<marker>`` is a **fresh random key per run** that a
clean baseline read proves absent, so any read-back of it under a payload — of *any*
value — is attributable pollution.

Detection-only: it proves the *sink* is reachable, not a working DOM-XSS — locating
a script/HTML gadget and chaining it to execution is handed to Strix. Sources:
https://portswigger.net/web-security/prototype-pollution/client-side ·
https://github.com/BlackFan/client-side-prototype-pollution. See docs/RESEARCH_GAPS.md Theme 6.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit, urlunsplit

# A distinctive prefix (the tool appends random hex per run) + the value we assign.
MARKER_PREFIX = "mooncsppz"
SENTINEL = "moonpolluted"

# Path notations that reach Object.prototype through a naive nested-merge parser —
# both the __proto__ and the constructor.prototype roots, in bracket and dotted form.
_PATHS = [
    ("proto_bracket", "__proto__[{m}]"),
    ("proto_dotted", "__proto__.{m}"),
    ("constructor_bracket", "constructor[prototype][{m}]"),
    ("constructor_dotted", "constructor.prototype.{m}"),
]


def read_script(marker: str) -> str:
    """A JS expression returning ``Object.prototype[marker]`` (or null if unset)."""

    return f"(window.Object.prototype[{json.dumps(marker)}] ?? null)"


def hashchange_script(marker: str) -> str:
    """For hash vectors: re-set ``location.hash`` to fire a ``hashchange`` (routers
    that parse the fragment only on that event, not on initial load), then read the
    marker after a tick. Returns a Promise Playwright awaits."""

    m = json.dumps(marker)
    return ("new Promise(function(res){try{var h=location.hash;location.hash='';"
            "location.hash=h;}catch(e){}setTimeout(function(){"
            "res(window.Object.prototype[" + m + "] ?? null);}, 80);})")


def _with_query(url: str, raw: str) -> str:
    sp = urlsplit(url)
    q = f"{sp.query}&{raw}" if sp.query else raw
    return urlunsplit(sp._replace(query=q))


def _with_hash(url: str, raw: str) -> str:
    return urlunsplit(urlsplit(url)._replace(fragment=raw))


def vectors(url: str, marker: str, sentinel: str = SENTINEL) -> list[tuple[str, str, bool]]:
    """Every (label, polluted_url, is_hash) to try — each path in both the query and
    the hash (client-side PP fires from either source)."""

    out: list[tuple[str, str, bool]] = []
    for name, tmpl in _PATHS:
        payload = f"{tmpl.format(m=marker)}={sentinel}"
        out.append((f"query:{name}", _with_query(url, payload), False))
        out.append((f"hash:{name}", _with_hash(url, payload), True))
    return out


def assess(baseline_value: object, vector_value: object) -> bool:
    """A vector confirms CSPP when the fresh random marker was **absent** on the clean
    baseline yet **present** (any value) after the payload — so the write is
    attributable to us. Value-agnostic: some parsers set the key to ``true``/``""``
    rather than our sentinel, which is still a real pollution."""

    return baseline_value is None and vector_value is not None
