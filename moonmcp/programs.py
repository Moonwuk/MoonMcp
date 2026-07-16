"""Bug-bounty program / engagement profiles.

A researcher juggles many programs at once, and every program tends to want its
own **identifying header** on your traffic — HackerOne wants
``X-HackerOne-Research: <handle>``, Bugcrowd and self-hosted programs each have
their own, and some ask you to tag requests with an email so their WAF/SOC does
not mistake authorised testing for an attack.  Keeping that straight by hand is
error-prone: point the wrong header (or the wrong scope) at the wrong target and
you are both rude and, potentially, out of scope.

A :class:`Program` bundles the things that change per engagement:

* its **scope** (in-scope and out-of-scope entries),
* a **custom bug-bounty header** (name + value) to attach to in-scope traffic,
* an optional per-program **User-Agent**,
* a free-form note.

The :class:`ProgramStore` holds them and tracks which one is *active*; the active
program's header + User-Agent are merged into every in-scope request by the HTTP
client (through the same provider path as :class:`~moonmcp.auth.AuthContext`, so
they only ever travel to in-scope hosts).  Profiles persist to
``MOONMCP_STATE_DIR`` when set, so they survive a restart.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field

_SAFE = re.compile(r"[^a-z0-9_.-]+")


def _slug(name: str) -> str:
    return _SAFE.sub("-", name.strip().lower()).strip("-") or "program"


def _coerce_str_list(raw: dict, key: str) -> None:
    """Coerce a persisted scope field to a clean ``list[str]`` in place.

    A hand-edited or corrupt ``programs.json`` could store ``scope`` / ``scope_exclude``
    as a bare string or ``null``. Without this, a string is iterated per-character when
    the profile is applied (so ``scope_exclude="admin.example.com"`` excludes the
    letters ``a``/``d``/``m``… and the intended host stays IN scope), and a ``null``
    crashes ``build_context`` on ``for entry in scope``. Normalise both here."""

    if key not in raw:
        return
    val = raw[key]
    if isinstance(val, str):
        raw[key] = [val] if val.strip() else []
    elif isinstance(val, list):
        raw[key] = [str(x) for x in val if str(x).strip()]
    else:
        raw[key] = []


def parse_header(spec: str) -> tuple[str, str]:
    """Parse a ``"Name: value"`` header spec into ``(name, value)``.

    Raises :class:`ValueError` if there is no ``:`` separator or an empty name.
    """

    if ":" not in spec:
        raise ValueError("header must be 'Name: value' (missing ':')")
    name, value = spec.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name:
        raise ValueError("header name is empty")
    return name, value


@dataclass
class Program:
    """One bug-bounty engagement profile."""

    name: str
    scope: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    header_name: str | None = None
    header_value: str | None = None
    user_agent: str | None = None
    note: str = ""

    def headers(self) -> dict[str, str]:
        """The header dict this program contributes to in-scope requests."""

        out: dict[str, str] = {}
        if self.header_name and self.header_value is not None:
            out[self.header_name] = self.header_value
        if self.user_agent:
            out["User-Agent"] = self.user_agent
        return out

    def summary(self) -> dict:
        """A JSON-friendly overview (no secrets — a bounty header is an identifier)."""

        return {
            "name": self.name,
            "scope": list(self.scope),
            "scope_exclude": list(self.scope_exclude),
            "header": f"{self.header_name}: {self.header_value}" if self.header_name else None,
            "user_agent": self.user_agent,
            "note": self.note,
        }


class ProgramStore:
    """Named engagement profiles with an active selection (optional disk persistence)."""

    def __init__(self, state_dir: str | None = None) -> None:
        self.state_dir = state_dir or None
        self._programs: dict[str, Program] = {}
        self._active: str | None = None
        self._load()

    # -- persistence -------------------------------------------------------
    def _path(self) -> str | None:
        if not self.state_dir:
            return None
        return os.path.join(self.state_dir, "programs.json")

    def _load(self) -> None:
        path = self._path()
        if not path or not os.path.exists(path):
            return
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        for raw in data.get("programs", []):
            if not isinstance(raw, dict):
                continue
            _coerce_str_list(raw, "scope")
            _coerce_str_list(raw, "scope_exclude")
            try:
                prog = Program(**{k: raw[k] for k in raw if k in Program.__dataclass_fields__})
            except TypeError:
                continue
            self._programs[prog.name] = prog
        active = data.get("active")
        if active in self._programs:
            self._active = active

    def _save(self) -> None:
        path = self._path()
        if not path:
            return
        try:
            os.makedirs(self.state_dir, exist_ok=True)  # type: ignore[arg-type]
            payload = {
                "active": self._active,
                "programs": [asdict(p) for p in self._programs.values()],
            }
            with open(path, "w") as fh:
                json.dump(payload, fh, indent=2)
        except OSError:
            pass

    # -- mutation ----------------------------------------------------------
    def add(self, program: Program) -> Program:
        program.name = program.name.strip()
        if not program.name:
            raise ValueError("program name is required")
        self._programs[program.name] = program
        self._save()
        return program

    def remove(self, name: str) -> bool:
        existed = self._programs.pop(name, None) is not None
        if existed and self._active == name:
            self._active = None
        if existed:
            self._save()
        return existed

    def use(self, name: str) -> Program:
        if name not in self._programs:
            raise KeyError(name)
        self._active = name
        self._save()
        return self._programs[name]

    # -- querying ----------------------------------------------------------
    def get(self, name: str) -> Program | None:
        return self._programs.get(name)

    def list(self) -> list[Program]:
        return list(self._programs.values())

    @property
    def active_name(self) -> str | None:
        return self._active

    @property
    def active(self) -> Program | None:
        return self._programs.get(self._active) if self._active else None

    def active_headers(self) -> dict[str, str]:
        """Headers contributed by the active program (empty if none active)."""

        prog = self.active
        return prog.headers() if prog else {}

    @classmethod
    def from_env(cls) -> ProgramStore:
        return cls(state_dir=os.environ.get("MOONMCP_STATE_DIR"))
