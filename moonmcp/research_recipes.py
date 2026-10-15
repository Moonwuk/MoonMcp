"""Two built-in application contracts; no importable/user-supplied recipes."""
from dataclasses import dataclass
from pathlib import Path

IMAGE = "python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"
DEFAULT_RECIPE = "sqlite-orders-v1"


@dataclass(frozen=True)
class Recipe:
    id: str
    app: Path
    resource_type: str
    collection: str
    register: str
    login: str
    identity: str
    authentication: str


_ORDERS = Recipe(DEFAULT_RECIPE, Path(__file__).with_name("research_app.py"),
                 "order", "/orders", "/register", "/login", "/me", "bearer")
_NOTES = Recipe("sqlite-notes-v1", Path(__file__).with_name("research_notes_app.py"),
               "note", "/notes", "/accounts", "/session", "/identity", "cookie_session")


def recipe(ident: str = DEFAULT_RECIPE) -> Recipe:
    if ident == _ORDERS.id:
        return _ORDERS
    if ident == _NOTES.id:
        return _NOTES
    raise ValueError("Unsupported built-in research recipe")


def recipes() -> tuple[Recipe, ...]:
    return _ORDERS, _NOTES
