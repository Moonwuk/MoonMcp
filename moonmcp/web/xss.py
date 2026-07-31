"""Reflected-XSS detection — HTML-context-aware, escape-analysis based (low false-positive).

Reflecting user input is NOT XSS. Reflecting it **unescaped**, in a context where the
reflected metacharacters are syntactically meaningful, is. The discipline:

1. inject a unique canary wrapped around the four XSS metacharacters (``< > " '``);
2. find where the canary lands and, with a single-pass HTML tokenizer, determine the exact
   **context** — HTML text, a quoted / unquoted attribute value, a value-START of a URL
   attribute that actually executes ``javascript:`` (``<a href>``, ``<iframe src>``, form
   actions, ``<script src>``…), a ``<script>`` / RAWTEXT / RCDATA element
   (``<title>``/``<textarea>``/``<style>``…), or an HTML comment;
3. measure which specials survived **unescaped** between the two canary anchors;
4. flag a context ONLY when the metacharacter it needs to break out survives.

The tokenizer (not ``rfind`` heuristics) is what makes it correct: an ``=`` inside a quoted
value can't be mistaken for an attribute start, a stray quote in earlier JS can't flip the
context, ``case`` / ``type=`` are handled, and — per the HTML spec — a RAWTEXT/RCDATA element
is only closed by ``</name>`` followed by a proper terminator, so a ``</scriptX`` lookalike
can't fool the parser into leaving the element (which would flip an inert reflection into a
false "attribute breakout"). A page that HTML-encodes ``<``/``"`` is never flagged.

Requirement per context: HTML text, a RAWTEXT/RCDATA element (``<title>``…) and ``<script>``
all break out with an unescaped ``<`` (``<tag>`` / ``</title>`` / ``</script>`` — a raw ``<``
implies a raw ``/`` too); a ``"``-quoted attribute needs its own ``"``; a ``'``-quoted one its
``'``; an UNQUOTED attribute is a lead with no metacharacter at all (a literal space injects a
new event-handler attribute — spaces are never HTML-encoded — and a surviving ``>`` also closes
the tag); the START of a script-executing URL attribute is injectable via a ``javascript:``
scheme (or a protocol-relative ``//host`` for ``<script src>``) with no metacharacters. Verdict
is a **lead** — proving execution needs a browser (CSP can defuse it) or Strix. Pure/offline
analysers here; the ``xss_probe`` tool does the fetching.
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
# Characters that terminate a RAWTEXT/RCDATA end-tag name (HTML spec): only when `</name` is
# followed by one of these (or EOF) is it an *appropriate* end tag that closes the element.
_TAG_TERMINATORS = frozenset(" \t\n\r\f/>")
_URL_WS = frozenset(" \t\n\r\f")  # leading URL whitespace browsers strip before scheme parse
# (element, attribute) pairs where a value-START reflection genuinely executes: `javascript:`
# fires on navigation/submit, and `<script src>` loads a protocol-relative attacker script.
# Deliberately tight — `<img src>`, `<link href>`, `poster`, `background`, `cite` do NOT run
# `javascript:`, so classifying them as URL leads would be a false positive; they fall through
# to normal attribute analysis (breakout still requires the surviving quote).
_JS_URL_SINKS = {
    ("a", "href"), ("a", "xlink:href"), ("area", "href"),
    ("form", "action"), ("button", "formaction"), ("input", "formaction"),
    ("iframe", "src"), ("frame", "src"), ("script", "src"),
}
_NEVER = {"\x00"}  # a requirement no single special can satisfy (an inert context)

# context -> (metachars that MUST survive unescaped to break out, human note)
_REQUIREMENTS: dict[str, tuple[set[str], str]] = {
    "html_text":     ({"<"},  "reflected in HTML text — an unescaped '<' opens an injected tag"),
    "rawtext":       ({"<"},  "reflected in a <{elem}> RAWTEXT/RCDATA element — an unescaped '<' allows "
                              "the '</{elem}>' break-out into script-capable markup"),
    "attr_double":   ({'"'},  "reflected in the \"-quoted '{attr}' attribute of <{elem}> — an unescaped "
                              "'\"' breaks out of the value"),
    "attr_single":   ({"'"},  "reflected in the '-quoted '{attr}' attribute of <{elem}> — an unescaped "
                              "\"'\" breaks out of the value"),
    "attr_unquoted": (set(),  "reflected in the UNQUOTED '{attr}' attribute of <{elem}> — a literal space "
                              "injects a new event-handler attribute (spaces are never HTML-encoded; a "
                              "surviving '>' also closes the tag). Confirm spaces aren't stripped"),
    "url":           (set(),  "reflected at the START of the <{elem}> '{attr}' URL sink — a javascript: "
                              "scheme (or protocol-relative //host for <script src>) injects with NO "
                              "metacharacters (confirm the value isn't scheme-validated)"),
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
    at_value_start = False  # value entered, only leading whitespace consumed (controls the scheme)

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
            end = i + 2 + len(raw_elem)
            if c == "<" and before[i + 1:i + 2] == "/" \
                    and before[i + 2:end].lower() == raw_elem \
                    and (end >= n or before[end] in _TAG_TERMINATORS):
                mode = "tag"
                is_end = True
                attr, quote, in_value = "", "", False
                i = end
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
            elif c not in _URL_WS:
                at_value_start = False  # leading whitespace is stripped by the URL parser → keep the start
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
        if at_value_start and not is_end and (raw_elem, attr) in _JS_URL_SINKS:
            return "url", raw_elem, attr
        if quote == '"':
            return "attr_double", raw_elem, attr
        if quote == "'":
            return "attr_single", raw_elem, attr
        return "attr_unquoted", raw_elem, attr
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
        note = note.replace("{elem}", element or "").replace("{attr}", attr or "")
        refl = Reflection(context=context, unescaped=unescaped, injectable=injectable,
                          element=element, attr=attr, note=note)
        cur = seen.get(context)
        if cur is None or (injectable and not cur.injectable):
            seen[context] = refl
    return list(seen.values())
