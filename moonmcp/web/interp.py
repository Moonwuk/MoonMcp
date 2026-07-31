"""Generic differential "interpretation" prober (Backslash Powered Scanner-style).

Most injection probes look for a KNOWN signature of a KNOWN vulnerability class.
This one asks a more basic question first: is this parameter's value being
*parsed/interpreted* at all, or just stored/echoed as an opaque blob? It sends a
handful of small, distinctive markers — each built to reveal ONE kind of
character-level processing (escape-sequence handling, quote/string-context
handling, null-byte truncation, path-segment normalization, template/structural-
token handling) — and checks whether the echoed value matches what was literally
sent.

A single marker firing is a coin-flip (a WAF or encoder could incidentally strip
one character class); TWO OR MORE independent markers agreeing is much harder to
explain by chance — the corroboration bar this tool requires before calling
anything more than a "weak" signal, mirroring the same false-positive discipline
`ssti_probe`'s multi-engine downgrade uses.

This tool never asserts a specific vulnerability class. Its output is a LEAD
pointing at which class-specific probe to run next (`sqli_probe`, `cmdi_probe`,
`lfi_probe`, `ssti_probe`, `parser_diff_probe`, ...) — by design strictly WEAKER
than any of those probes' own verdicts.
"""

from __future__ import annotations

import html
import json
from urllib.parse import quote

# (name, template ({c} = the control marker), suggested next tools, what
# "interpreted" means for this marker).
MARKERS: list[tuple[str, str, tuple[str, ...], str]] = [
    ("backslash", "{c}\\", ("sqli_probe", "cmdi_probe"),
     "a trailing backslash was stripped, doubled, or otherwise altered — evidence "
     "of escape-sequence processing (string/shell/regex context)."),
    ("quote", "{c}'", ("sqli_probe", "cmdi_probe", "nosqli_probe"),
     "a trailing single quote was stripped, doubled, or backslash-escaped — "
     "evidence of string-literal context handling."),
    ("null_byte", "{c}\x00{c}TAIL", ("lfi_probe", "cmdi_probe"),
     "the value was altered at or after a NUL byte — evidence of C-string/"
     "buffer-style handling (common in native file/exec sinks)."),
    ("path_dot_segment", "{c}/./{c}TAIL", ("lfi_probe", "path_bypass_probe"),
     "a /./ path segment was collapsed or altered — evidence the value passes "
     "through path normalization somewhere in the stack."),
    ("brace", "{c}{}{c}", ("ssti_probe", "parser_diff_probe"),
     "a bare {} pair was stripped or altered — evidence of template/structural-"
     "token handling."),
]


def build_probe(control: str, template: str) -> str:
    """Fill *template* (one of `MARKERS`' templates) with *control* (pure)."""

    return template.replace("{c}", control)


_DUPLICABLE_TRAILERS = "\\'\"{}"


def _reencodings(sent: str) -> list[str]:
    """The ways a correctly-behaving endpoint might *re-serialize* ``sent`` on echo
    without interpreting its special characters: percent-encoded (a raw still-encoded
    query reflected into a canonical `<link>`/`og:url`/form action), JSON-string-
    escaped (`\\`->`\\\\`, NUL->`\\u0000`), or HTML-entity-escaped (`'`->`&#x27;`).
    Only forms that actually changed something are returned (a no-op re-encoding is
    just the decoded echo, handled separately)."""

    forms = [quote(sent, safe=""), json.dumps(sent)[1:-1], html.escape(sent, quote=True)]
    return [f for f in forms if f != sent]


def assess_marker(control: str, template: str, body: str, *, window: int = 40) -> dict:
    """Does *body* show evidence the marker's special character(s) were consumed or
    transformed by a *sink* (interpreted), rather than merely echoed — possibly
    re-serialized by the response format? (pure)

    Locates the first occurrence of *control*; if absent, the marker's fate is
    unobservable. Then classifies the echo:

    * A faithful **re-encoding** of the whole value (percent / JSON / HTML) is NOT
      interpretation — the special chars were reproduced, just serialized. This is
      the fix for a benign reflecting/JSON-echo endpoint (which reflects `%5C`, or
      JSON-doubles `\\`->`\\\\`, or turns `'`->`&#x27;`) otherwise reaching the top
      "corroborated" verdict on a non-injectable target.
    * A faithful **decoded** echo is not interpretation either — UNLESS the trailing
      special char is DOUBLED in a way no response format produces (SQL `'`->`''`;
      JSON's `\\`->`\\\\` was already absorbed as a re-encoding above).
    * Anything else (the char stripped, a `/./` collapsed, a NUL truncation, a
      sink-level escape) means the value was interpreted."""

    sent = build_probe(control, template)
    idx = body.find(control)
    if idx < 0:
        return {"observed": False, "interpreted": False}
    reencs = _reencodings(sent)
    maxlen = max([len(sent), *(len(f) for f in reencs)]) + window
    slice_ = body[idx: idx + maxlen]
    if any(slice_.startswith(f) for f in reencs):
        return {"observed": True, "interpreted": False}   # response-format re-encoding, benign
    if slice_.startswith(sent):
        trailing = sent[-1]
        if trailing in _DUPLICABLE_TRAILERS and slice_[len(sent): len(sent) + 1] == trailing:
            return {"observed": True, "interpreted": True}   # sink-level doubling (e.g. SQL '')
        return {"observed": True, "interpreted": False}
    return {"observed": True, "interpreted": True}           # stripped / normalized / escaped


def suggest_next(hits: list[dict]) -> list[str]:
    """The de-duplicated, order-preserving union of suggested next tools across
    every marker whose result was `interpreted` (pure)."""

    by_name = {name: tools for name, _t, tools, _d in MARKERS}
    out: list[str] = []
    for h in hits:
        if not h.get("interpreted"):
            continue
        for tool in by_name.get(h.get("marker", ""), ()):
            if tool not in out:
                out.append(tool)
    return out


def verdict(hits: list[dict]) -> str:
    """`"none"` / `"weak"` / `"corroborated"` from the count of markers that fired
    (pure). Two or more independent markers agreeing is the corroboration bar —
    see the module docstring."""

    count = sum(1 for h in hits if h.get("interpreted"))
    if count >= 2:
        return "corroborated"
    if count == 1:
        return "weak"
    return "none"
