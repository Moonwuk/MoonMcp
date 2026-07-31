"""Reflected-XSS detection — context-aware, escape-analysis based (low false-positive).

Reflecting user input is NOT XSS. Reflecting it **unescaped**, in a context where the
reflected metacharacters are syntactically meaningful, is. So the discipline here is:

1. reflect a unique canary and find every place it lands in the response;
2. classify the HTML/JS **context** around each reflection (html-text / attribute value /
   ``<script>`` block / JS string / HTML comment);
3. measure which XSS metacharacters (``< > " '``) survive **unescaped** at that spot (a
   second probe wraps the four specials between two canary halves so the exact reflection
   is locatable and each character's fate is readable);
4. flag a context only when the metacharacters that context actually needs to break out
   survive unescaped — e.g. a double-quoted attribute needs ``"``; html-text needs ``<``.

A page that reflects the canary but HTML-encodes ``<``/``"`` (``&lt;`` / ``&quot;``) is
therefore NOT flagged. The verdict is a **lead** ("injectable context — script-capable"):
proving actual JS execution needs a browser (the DOM/exec lane) or Strix, since a reflected,
unescaped ``<script>`` can still be defused by CSP. Pure/offline analysers here; the
``xss_probe`` tool does the fetching. In scope only.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

# The four metacharacters that matter for HTML/JS injection. The probe embeds them between
# two copies of the canary so we can locate the exact reflection and read each one's fate.
_SPECIALS = "<>\"'"


def make_canary() -> str:
    """A unique, alnum-only marker (survives most reflection contexts verbatim)."""

    return "moonxss" + secrets.token_hex(4)


def specials_probe(canary: str) -> str:
    """The value to inject: ``<canary><>"'<canary>`` — a leading break-out attempt plus the
    four specials fenced between two canary anchors so their escaping is readable on reflect."""

    return f"{canary}{_SPECIALS}{canary}"


# What each context needs to break OUT and inject script.
# (context -> (the metachar set that MUST survive unescaped, human note))
# NB: `<` is what an empty-set requirement is never — for the <script> STRING contexts the
# reliable break-out is `</script>` (the HTML parser closes the element regardless of JS
# string state), so they require `<`, not a bare quote — a backslash-escaped `\"` still
# contains a literal `"` byte yet is safe. An HTML comment needs `-->` (which is not one of
# our four specials) so it is reported as a context but never auto-flagged injectable.
_NEVER = {"-->"}  # a sentinel requirement no single special can satisfy
_CONTEXT_REQUIREMENTS: dict[str, tuple[set[str], str]] = {
    "html_text":            ({"<"},   "reflected in HTML text — an unescaped '<' opens an injected tag"),
    "attr_double":          ({'"'},   "reflected in a \"-quoted attribute — an unescaped '\"' breaks out"),
    "attr_single":          ({"'"},   "reflected in a '-quoted attribute — an unescaped \"'\" breaks out"),
    "attr_unquoted":        ({">"},   "reflected in an UNQUOTED attribute — an unescaped '>' closes the tag"),
    "script_string_double": ({"<"},   "reflected in a \"-quoted JS string in <script> — '</script>' breaks out"),
    "script_string_single": ({"<"},   "reflected in a '-quoted JS string in <script> — '</script>' breaks out"),
    "script_raw":           (set(),   "reflected in raw <script> code — arbitrary JS injectable"),
    "html_comment":         (_NEVER,  "reflected in an HTML comment — needs '-->' to break out (verify manually)"),
}


@dataclass
class Reflection:
    context: str
    unescaped: set[str] = field(default_factory=set)   # which of < > " ' survived literally
    injectable: bool = False
    note: str = ""


def _classify_context(before: str) -> str:
    """Classify the reflection context from the text immediately BEFORE it."""

    # Inside a <script> block? (an open <script ...> with no </script> after it, before us).
    last_open = before.rfind("<script")
    if last_open != -1 and before.rfind("</script") < last_open:
        tail = before[last_open:]
        # inside a JS string literal within the script?
        dq = tail.count('"')
        sq = tail.count("'")
        if dq % 2 == 1:
            return "script_string_double"
        if sq % 2 == 1:
            return "script_string_single"
        return "script_raw"

    # Inside an HTML comment? (<!-- with no --> after it).
    last_cmt = before.rfind("<!--")
    if last_cmt != -1 and before.rfind("-->") < last_cmt:
        return "html_comment"

    # Inside a tag (an unclosed '<' — a '<' more recent than the last '>').
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt != -1 and last_lt > last_gt:
        # attribute value — determine the quoting from the char run just before the reflection.
        m = re.search(r'=\s*(["\']?)[^"\'=<>]*$', before[last_lt:])
        if m:
            q = m.group(1)
            if q == '"':
                return "attr_double"
            if q == "'":
                return "attr_single"
            return "attr_unquoted"
        return "attr_unquoted"

    return "html_text"


def analyze(body: str, canary: str) -> list[Reflection]:
    """Given a response *body* to the specials_probe(canary) injection, return one Reflection
    per distinct reflected context, each recording which specials survived unescaped and
    whether that makes the context injectable."""

    if not body:
        return []
    anchor = re.compile(re.escape(canary) + r"(.*?)" + re.escape(canary), re.S)
    seen: dict[str, Reflection] = {}
    for m in anchor.finditer(body):
        middle = m.group(1)
        # which of the four specials survived LITERALLY between the two canary anchors?
        unescaped = {c for c in _SPECIALS if c in middle}
        before = body[:m.start()]
        ctx = _classify_context(before)
        req, note = _CONTEXT_REQUIREMENTS.get(ctx, (set(), ""))
        # injectable when EVERY metachar the context needs to break out survived unescaped
        # (an empty requirement set — unquoted attr / raw script — is injectable on reflection).
        injectable = req.issubset(unescaped)
        refl = Reflection(context=ctx, unescaped=unescaped, injectable=injectable, note=note)
        # keep the strongest (injectable wins) per context
        cur = seen.get(ctx)
        if cur is None or (injectable and not cur.injectable):
            seen[ctx] = refl
    return list(seen.values())
