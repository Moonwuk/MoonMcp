"""Known-vulnerable client-side JS library detection (Retire.js-lite).

Matches JS filenames/URLs (and, best-effort, an in-body version banner like
`/*! jQuery v1.9.1 */`) already surfaced by `analyze_js`/`crawl` against a small
bundled table of historically-vulnerable library versions — pure regex + a
version-tuple comparison, no content-hash database to maintain. That's a
deliberate trade: Retire.js's fuller coverage costs an ongoing signature-database
update; this trades completeness for zero maintenance dependency, at the price
of missing a library that was renamed or has no version string in its filename.
The bundled table itself still needs periodic refresh as new CVEs land — this is
a curated, illustrative set, not exhaustive.

100% passive pattern matching over data other tools already fetched — same risk
profile as `extract_secrets`/`deserialize_fingerprint`.
"""

from __future__ import annotations

import re


def _v(version: str) -> tuple[int, ...]:
    """Parse a dotted version string into a comparable int tuple (pure). A
    non-numeric component truncates the tuple there (``"1.9.1-beta"`` -> ``(1,9,1)``)."""

    parts: list[int] = []
    for chunk in version.split("."):
        m = re.match(r"\d+", chunk)
        if not m:
            break
        parts.append(int(m.group(0)))
    return tuple(parts) or (0,)


def _lib_pattern(name: str) -> str:
    """A filename/query-string version pattern for a CDN-style asset named *name*
    (e.g. ``jquery-1.9.1.min.js``, ``jquery.js?ver=1.9.1``). The ``.min`` suffix
    (if present) comes AFTER the version in real CDN filenames."""

    return (rf"{name}[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"
           rf"|{name}\.js\?[^\"']*?v(?:er)?=(\d+\.\d+\.\d+)"
           rf"|{name}\s+v(\d+\.\d+\.\d+)")


def _is_vulnerable(version: str, fixed: str | tuple[str, ...]) -> bool:
    """Is *version* below its own branch's first-fixed version? *fixed* is a single
    boundary, OR — for a library with parallel maintained lines (e.g. Bootstrap 3.4.x
    backported the fixes into the 3.x line) — a tuple of per-major-branch fixes. A version
    on a major line with a recorded fix is vulnerable iff it precedes that fix; a version
    on an OLDER unfixed major is vulnerable; a version on a NEWER major (a later rewrite) is
    not covered (patched)."""

    vt = _v(version)
    fixes = (fixed,) if isinstance(fixed, str) else tuple(fixed)
    same_major = [f for f in fixes if _v(f)[0] == vt[0]]
    if same_major:
        return vt < _v(same_major[0])
    return vt[0] < max(_v(f)[0] for f in fixes)


def _applicable_fix(version: str, fixed: str | tuple[str, ...]) -> str:
    fixes = (fixed,) if isinstance(fixed, str) else tuple(fixed)
    same_major = [f for f in fixes if _v(f)[0] == _v(version)[0]]
    return same_major[0] if same_major else fixes[-1]


# (library, pattern, first-fixed version(s), CVEs, summary, severity). A small,
# deliberately-curated set — see the module docstring on maintenance scope. `fixed` is a
# single version, or a tuple of per-branch fixes for libraries with parallel lines.
_SIGNATURES: list[tuple[str, str, str | tuple[str, ...], tuple[str, ...], str, str]] = [
    ("jQuery", _lib_pattern("jquery"), "3.5.0", ("CVE-2020-11022", "CVE-2020-11023"),
     "jQuery <3.5.0: .html()/.htmlPrefilter() can execute untrusted <option>/<script>-"
     "like markup passed to .html(), .append(), etc. — a DOM XSS sink.", "high"),
    ("AngularJS", _lib_pattern("angular"), "1.8.0", ("CVE-2020-7676",),
     "AngularJS <1.8.0: known Content-Security-Policy / expression-sandbox bypasses "
     "enabling template-injection-driven XSS.", "high"),
    ("Lodash", _lib_pattern("lodash"), "4.17.21",
     ("CVE-2018-16487", "CVE-2019-10744", "CVE-2020-8203", "CVE-2020-28500"),
     "Lodash <4.17.21: prototype-pollution issues in _.merge/_.mergeWith/"
     "_.zipObjectDeep/_.set and a ReDoS in _.trim — a common gadget for chained "
     "exploitation.", "high"),
    ("Moment.js", _lib_pattern("moment"), "2.29.2", ("CVE-2022-24785",),
     "Moment.js <2.29.2: a ReDoS in its locale-string parser.", "medium"),
    ("Handlebars", _lib_pattern("handlebars"), "4.5.3", ("CVE-2019-19919",),
     "Handlebars <4.5.3: a prototype-pollution gadget via crafted templates "
     "({{__proto__}} lookup chains) that can lead to arbitrary code execution.", "high"),
    ("Bootstrap", _lib_pattern("bootstrap"), ("3.4.0", "4.1.2"),
     ("CVE-2018-14041", "CVE-2018-14042"),
     "Bootstrap <3.4.0 (3.x) / <4.1.2 (4.x): XSS via the tooltip/popover/scrollspy "
     "data-target/data-container attributes (untrusted HTML reaching the collapse/affix "
     "targets). 3.4.0 backported the fixes into the 3.x line.", "medium"),
]

_COMPILED = [(lib, re.compile(pat, re.IGNORECASE), fixed, cves, summary, sev)
            for lib, pat, fixed, cves, summary, sev in _SIGNATURES]


def scan(source: str) -> list[dict]:
    """Scan one script URL/filename (or a JS snippet containing a version banner)
    for a known-vulnerable library version (pure). A single source could
    theoretically match more than one library banner, hence a list."""

    hits: list[dict] = []
    for lib, pattern, fixed, cves, summary, sev in _COMPILED:
        m = pattern.search(source)
        if not m:
            continue
        version = next((g for g in m.groups() if g), None)
        if not version or not _is_vulnerable(version, fixed):
            continue
        hits.append({"library": lib, "version": version, "fixed_version": _applicable_fix(version, fixed),
                    "cves": list(cves), "severity": sev, "summary": summary,
                    "source": source[:200]})
    return hits


def scan_all(sources: list[str]) -> list[dict]:
    """Scan every source (script URLs, filenames, JS snippets) and return the
    union of hits, de-duplicated by (library, version) (pure)."""

    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for src in sources:
        for hit in scan(src):
            key = (hit["library"], hit["version"])
            if key in seen:
                continue
            seen.add(key)
            out.append(hit)
    return out
