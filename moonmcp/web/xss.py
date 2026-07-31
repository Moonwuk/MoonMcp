"""Reflected-XSS detection — HTML-context-aware, escape-analysis based (low false-positive).

Reflecting user input is NOT XSS. Reflecting it **unescaped**, in a context where the
reflected metacharacters are syntactically meaningful, is. The discipline:

1. inject a unique canary wrapped around the four XSS metacharacters (``< > " '``);
2. find where the canary lands and, with a single-pass HTML tokenizer, determine the exact
   **context** — HTML text, a quoted / unquoted attribute value, a ``href``/``src`` URL
   value, a ``<script>`` / RAWTEXT / RCDATA element (``<title>``/``<textarea>``/``<style>``…),
   or an HTML comment;
3. measure which specials survived **unescaped** between the two canary anchors;
4. flag a context ONLY when the metacharacter it needs to break out survives.

The tokenizer (not ``rfind`` heuristics) is what makes it correct: an ``=`` inside a quoted
value can't be mistaken for an attribute start, a stray quote in earlier JS can't flip the
context, and case / ``type=`` are handled. A page that HTML-encodes ``<``/``"`` is never
flagged. Note the requirement per context: HTML text, a RAWTEXT/RCDATA element (``<title>``…)
and ``<script>`` all break out with an unescaped ``<`` (``<tag>`` / ``</title>`` / ``</script>``
— a raw ``<`` implies a raw ``/`` too); a quoted attribute needs its own quote; an unquoted one
needs ``>``; the START of a URL attribute is injectable via a ``javascript:`` scheme with no
metacharacters at all. Verdict is a **lead** — proving execution needs a browser (CSP can
defuse it) or Strix. Pure/offline analysers here; the ``xss_probe`` tool does the fetching.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

_SPECIALS = "<>\"'"
# Fully HTML-encoded, the four specials span ~24 bytes (`&lt;&gt;&quot;&#39;`); bound the
# anchor gap just above that so a reflection whose second anchor was truncated can't mis-pair
# with a DIFFERENT, distant reflection and count the page's own markup between them as
# "surviving" specials — a false positive on a fully-escaping (secure) app.
_MAX_GAP = 32

# Elements whose content is RAWTEXT / RCDATA: markup inside is inert UNTIL the element's own
# end tag, so break-out is `</elem>` — which, like a normal tag, needs an unescaped `<`.
_RAWTEXT = {"script", "style", "xmp", "iframe", "noembed", "noframes", "noscript",
            "textarea", "title"}
# URL-bearing attributes whose VALUE START a reflection controls → a javascript:/data: scheme.
_URL_ATTRS = {"href", "src", "action", "formaction", "xlink:href", "poster", "background",
              "cite", "data", "srcdoc"}
_NEVER = {"\x00"}  # a requirement no single special can satisfy (an inert context)

# context -> (metachars that MUST survive unescaped to break out, human note)
_REQUIREMENTS: dict[str, tuple[set[str], str]] = {
    "html_text":     ({"<"},  "reflected in HTML text — an unescaped '<' opens an injected tag"),
    "rawtext":       ({"<"},  "reflected in a <{elem}> RAWTEXT/RCDATA element — an unescaped '<' allows "
                              "the '</{elem}>' break-out into script-capable markup"),
    "attr_double":   ({'"'},  "reflected in a \"-quoted attribute — an unescaped '\"' breaks out"),
    "attr_single":   ({"'"},  "reflected in a '-quoted attribute — an unescaped \"'\" breaks out"),
    "attr_unquoted": ({">"},  "reflected in an UNQUOTED attribute — an unescaped '>' closes the tag"),
    "url":           (set(),  "reflected at the START of the '{elem}' URL attribute — a javascript:/data: "
                              "scheme injects with NO metacharacters (confirm the scheme isn't validated)"),
    "comment":       (_NEVER, "reflected in an HTML comment — needs '-->' to break out (verify manually)"),
}


def make_canary() -> str:
    """A unique, alnum-only marker (survives most reflection contexts verbatim)."""

    return "moonxss" + secrets.token_hex(4)


def specials_probe(canary: str) -> str:
    """The value to inject: ``<canary><>"'<canary>`` — a leading break-out attempt plus the
    four specials fenced between two canary anchors so their escaping is readable on reflect."""

    return f"{canary}{_SPECIALS}{canary}"


@dataclass
class Reflection:
    context: str
    unescaped: set[str] = field(default_factory=set)
    injectable: bool = False
    element: str = ""
    attr: str = ""
    note: str = ""


def _scan_context(before: str) -> tuple[str, str, str]:
    """Single-pass HTML tokenizer over *before* (everything up to the reflection point).
    Returns ``(context, element, attr)`` describing the context AT the end of *before*."""

    i, n = 0, len(before)
    mode = "data"           # data | comment | rawtext | tag
    raw_elem = ""           # element name while in rawtext mode / being parsed as a start tag
    is_end = False          # the tag currently being parsed is an end tag
    attr = ""               # current attribute name (lowercased)
    quote = ""              # current attribute-value quote char (''=unquoted)
    in_value = False
    at_value_start = False  # value entered, nothing consumed yet (reflection controls the scheme)

    while i < n:
        c = before[i]

        if mode == "comment":
            if before.startswith("-->", i):
                mode = "data"
                i += 3
            else:
                i += 1
            continue

        if mode == "rawtext":
            if c == "<" and before[i + 1:i + 2] == "/" and \
                    before[i + 2:i + 2 + len(raw_elem)].lower() == raw_elem:
                mode = "tag"
                is_end = True
                attr, quote, in_value = "", "", False
                i += 2 + len(raw_elem)
            else:
                i += 1
            continue

        if mode == "data":
            if c == "<":
                if before.startswith("<!--", i):
                    mode = "comment"
                    i += 4
                    continue
                m = re.match(r"</?([a-zA-Z][a-zA-Z0-9:-]*)", before[i:])
                if m:
                    is_end = before[i + 1:i + 2] == "/"
                    raw_elem = m.group(1).lower()
                    mode = "tag"
                    attr, quote, in_value = "", "", False
                    i += m.end()
                    continue
            i += 1
            continue

        # mode == "tag"
        if in_value:
            if quote and c == quote:
                in_value = False
                quote, attr = "", ""
            elif not quote and c in " \t\n\r>":
                in_value = False
                attr = ""
                continue  # re-handle c (whitespace / '>') below
            else:
                at_value_start = False
            i += 1
            continue

        if c == ">":
            mode = "rawtext" if (not is_end and raw_elem in _RAWTEXT) else "data"
            if mode == "data":
                raw_elem = ""
            i += 1
            continue

        if c in " \t\n\r/":
            attr = ""
            i += 1
            continue

        if c == "=":
            i += 1
            while i < n and before[i] in " \t\n\r":
                i += 1
            if i < n and before[i] in "\"'":
                quote = before[i]
                i += 1
            else:
                quote = ""
            in_value = True
            at_value_start = True
            continue

        m = re.match(r"[^\s=/>]+", before[i:])
        if m:
            attr = m.group(0).lower()
            i += m.end()
            continue
        i += 1

    if mode == "comment":
        return "comment", "", ""
    if mode == "rawtext":
        return "rawtext", raw_elem, ""
    if mode == "tag" and in_value:
        if attr in _URL_ATTRS and at_value_start:
            return "url", "", attr
        if quote == '"':
            return "attr_double", "", attr
        if quote == "'":
            return "attr_single", "", attr
        return "attr_unquoted", "", attr
    return "html_text", "", ""


def analyze(body: str, canary: str) -> list[Reflection]:
    """Return one Reflection per distinct reflected context for a specials_probe(canary)
    injection, recording which specials survived unescaped and whether that is injectable."""

    if not body:
        return []
    anchor = re.compile(re.escape(canary) + r"(.{0," + str(_MAX_GAP) + r"}?)" + re.escape(canary), re.S)
    seen: dict[str, Reflection] = {}
    for m in anchor.finditer(body):
        middle = m.group(1)
        unescaped = {c for c in _SPECIALS if c in middle}
        context, element, attr = _scan_context(body[:m.start()])
        req, note = _REQUIREMENTS.get(context, (_NEVER, ""))
        injectable = req.issubset(unescaped)
        note = note.replace("{elem}", element or attr).replace("{elem}", element or attr)
        refl = Reflection(context=context, unescaped=unescaped, injectable=injectable,
                          element=element, attr=attr, note=note)
        cur = seen.get(context)
        if cur is None or (injectable and not cur.injectable):
            seen[context] = refl
    return list(seen.values())
