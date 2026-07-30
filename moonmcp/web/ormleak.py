"""ORM leak / relational-filter injection — a filter differential nuclei can't express.

When an app spreads untrusted params straight into an ORM filter (Django
``Model.objects.filter(**request.GET)``, Prisma ``where: req.query.filter``,
Rails/Ransack ``Model.ransack(params[:q])``), an attacker injects ORM *lookups* and
relational traversals to filter by fields they can't see (``password``, ``reset_token``,
``is_superuser``) and read them out character-by-character. This is elttam's "Leaking
More Than You Joined For"; there is no raw SQL and zero classic SQLi, so `sqli_probe`
and nuclei both miss it.

Detection (safe, differential — no value is ever read out): inject an ORM lookup as a
NEW filter kwarg with an **empty prefix** (``__startswith=`` matches every row) vs an
**unlikely prefix** (matches none). If the two produce a *reproducible* differential,
the lookup is applied as a filter — the hidden field is queryable. If the param is
ignored (not spread into a filter) both are identical → no finding.

Per-ORM lookup forms:
- Django  ``<field>__startswith`` / ``<rel>__<field>__startswith`` (double-underscore)
- Prisma  ``<base>[<field>][startsWith]`` (nested bracket object)
- Ransack ``<base>[<field>_start]`` (predicate suffix)

Weaponization (char-by-char extraction, the mass-assignment→privilege spread) →
`logic_probe`'s mass-assignment / Strix. Sources:
https://www.elttam.com/blog/leaking-more-than-you-joined-for ·
https://swisskyrepo.github.io/PayloadsAllTheThings/ORM%20Leak/ ·
https://hacktricks.wiki/en/pentesting-web/orm-injection.html . See docs/DATABASE_RESEARCH.md D.1.
"""

from __future__ import annotations

# Two unlikely-prefix values that should match no rows (the "none" side of the diff).
# They are the SAME semantically (both unmatchable) but of very different LENGTHS: a
# genuine "zero rows" page is value-independent, so both must render identically. If
# the response length instead tracks the injected value's length, the differential is
# mere reflection/echo of the param (canonical link, "no results for '<x>'", form
# re-population) — not an applied filter — and must be rejected. See assess_lookup.
CONTROL_NONE = "zqxjkMoon9174none"
CONTROL_NONE_ALT = "zqxjkMoon9174none" + "Wq7vLx0" * 6  # markedly longer, still unmatchable

# Hidden fields worth probing for (queryable = a leak surface).
_DJANGO_FIELDS = ["password", "is_superuser", "is_staff", "email", "api_key", "reset_token"]
_DJANGO_RELATIONS = ["user", "owner", "created_by"]
_NESTED_FIELDS = ["password", "email", "resetToken", "apiKey"]
_RANSACK_FIELDS = ["password", "email", "reset_password_token"]


def django_candidates() -> list[tuple[str, str]]:
    """(field-label, injected-param-name) for Django ``__startswith`` leak probes."""

    out = [(f, f"{f}__startswith") for f in _DJANGO_FIELDS]
    out += [(f"{rel}__{f}", f"{rel}__{f}__startswith")
            for rel in _DJANGO_RELATIONS for f in ("password", "email")]
    return out


def prisma_candidates(base: str) -> list[tuple[str, str]]:
    """(field-label, injected-param) for Prisma ``<base>[<field>][startsWith]`` probes."""

    b = base or "filter"
    return [(f, f"{b}[{f}][startsWith]") for f in _NESTED_FIELDS]


def ransack_candidates(base: str) -> list[tuple[str, str]]:
    """(field-label, injected-param) for Rails/Ransack ``<base>[<field>_start]`` probes."""

    b = base or "q"
    return [(f, f"{b}[{f}_start]") for f in _RANSACK_FIELDS]


def candidates(orm: str, base: str) -> list[tuple[str, str, str]]:
    """(orm-family, field-label, injected-param) for the selected ORM(s)."""

    o = (orm or "auto").lower()
    out: list[tuple[str, str, str]] = []
    if o in ("auto", "django"):
        out += [("django", lbl, p) for lbl, p in django_candidates()]
    if o in ("auto", "prisma"):
        out += [("prisma", lbl, p) for lbl, p in prisma_candidates(base)]
    if o in ("auto", "ransack"):
        out += [("ransack", lbl, p) for lbl, p in ransack_candidates(base if base != "filter" else "q")]
    return out


def looks_applied(all_pair: tuple, none_pair: tuple) -> bool:
    """Cheap gate: the empty-prefix ("all") and unlikely-prefix ("none") probes are
    each REPRODUCIBLE (both sends agree on status, length within a jitter floor) and
    DIFFER from each other beyond that floor — a *necessary-but-not-sufficient* sign
    the lookup is applied as a filter. Each element is ``(status, length)``.

    The jitter floor (derived from each arm's own paired sends, mirroring
    ``sqli_probe``) replaces the old byte-exact compare, which false-negatived every
    dynamic/authed page carrying a nonce/timestamp/CSRF token. Callers must still
    clear the reflection control in :func:`assess_lookup` before reporting.
    """

    (as1, al1), (as2, al2) = all_pair
    (ns1, nl1), (ns2, nl2) = none_pair
    tol = max(abs(al1 - al2), abs(nl1 - nl2)) + 16
    if as1 != as2 or ns1 != ns2:
        return False  # an arm is not reproducible → noise, not a filter
    return as1 != ns1 or abs(al1 - nl1) > tol


def assess_lookup(all_pair: tuple, none_pair: tuple, none_alt_pair: tuple) -> bool:
    """A hit requires :func:`looks_applied` AND a **reflection control**: a second
    no-match value of a very different length (``CONTROL_NONE_ALT``) must render the
    SAME page as the first ("no rows" is value-independent). If the response length
    tracks the injected value instead, the differential is an echo of the parameter,
    not an applied filter — so the "high-severity, field is queryable" verdict is
    withheld. Each element is ``(status, length)``.
    """

    if not looks_applied(all_pair, none_pair):
        return False
    (ns1, nl1), (ns2, nl2) = none_pair
    (xs1, xl1), (xs2, xl2) = none_alt_pair
    # Floor from the *none* arm's own reproducibility — do NOT let an unstable alt
    # arm inflate its own tolerance (that would absorb the very reflection signal
    # we are testing for). The alt control must be stable within this floor...
    tol = abs(nl1 - nl2) + 16
    if xs1 != xs2 or abs(xl1 - xl2) > tol:
        return False  # alt control not reproducible → can't trust the reflection check
    # ...and render the same page as the first no-match value (value-independent).
    return ns1 == xs1 and abs(nl1 - xl1) <= tol
