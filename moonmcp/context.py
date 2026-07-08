"""Shared application context and serialization helpers.

A single :class:`AppContext` bundles the settings, scope manager, rate governor
and HTTP client so every tool draws on the same rate limit and scope state.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from .config import Settings, load_settings
from .net.http import HttpClient
from .net.ratelimit import Governor
from .scope import ScopeManager


@dataclass
class AppContext:
    settings: Settings
    scope: ScopeManager
    governor: Governor
    http: HttpClient


def build_context(settings: Settings | None = None) -> AppContext:
    settings = settings or load_settings()
    scope = ScopeManager(enforce=settings.enforce_scope)
    for entry in settings.scope:
        scope.add(entry)
    for entry in settings.scope_exclude:
        scope.exclude(entry)
    governor = Governor(rate=settings.rate_limit, max_concurrency=settings.max_concurrency)
    http = HttpClient(
        governor,
        user_agent=settings.user_agent,
        default_timeout=settings.timeout,
    )
    return AppContext(settings=settings, scope=scope, governor=governor, http=http)


def to_dict(obj: object, *, drop_none: bool = True) -> object:
    """Recursively convert dataclasses/containers into JSON-friendly primitives."""

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out = {}
        for f in dataclasses.fields(obj):
            value = to_dict(getattr(obj, f.name), drop_none=drop_none)
            if drop_none and value is None:
                continue
            if drop_none and isinstance(value, (list, dict)) and len(value) == 0:
                # keep empty collections only if explicitly meaningful; drop by default
                continue
            out[f.name] = value
        return out
    if isinstance(obj, dict):
        return {k: to_dict(v, drop_none=drop_none) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_dict(v, drop_none=drop_none) for v in obj]
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return obj
