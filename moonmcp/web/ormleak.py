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

# An unlikely prefix value that should match no rows (the "none" side of the diff).
CONTROL_NONE = "zqxjkMoon9174none"

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


def assess_lookup(all_pair: tuple, none_pair: tuple, *, none_reflected: bool = False) -> bool:
    """An injected lookup is a hit when the empty-prefix ("all") and unlikely-prefix
    ("none") probes are each REPRODUCIBLE (both sends agree) and DIFFER from each
    other — i.e. the lookup is applied as a filter. Each element is ``(status, len)``.

    ``none_reflected`` guards the reflection false positive: the "all" value is empty and
    the "none" value is the 17-char ``CONTROL_NONE``, so an endpoint that merely ECHOES
    the param verbatim makes the "none" body ~17 bytes longer and manufactures a
    differential with no ORM filter involved. When the unlikely value is found reflected
    in the body, the differential is attributable to the echo, not to filtering, so it is
    suppressed. FN-safe: ``CONTROL_NONE`` matches no rows, so a genuine relational filter
    never surfaces it in the result data."""

    if none_reflected:
        return False
    a1, a2 = all_pair
    n1, n2 = none_pair
    return bool(a1 == a2 and n1 == n2 and a1 != n1)
