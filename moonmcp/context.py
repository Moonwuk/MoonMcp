"""Shared application context and serialization helpers.

A single :class:`AppContext` bundles the settings, scope manager, rate governor
and HTTP client so every tool draws on the same rate limit and scope state.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass

from .auth import AuthContext
from .config import Settings, load_settings
from .findings import FindingsStore
from .intel.oast import OastStore
from .monitor import SnapshotStore
from .net.http import HttpClient
from .net.ratelimit import Governor
from .scope import ScopeManager


@dataclass
class AppContext:
    settings: Settings
    scope: ScopeManager
    governor: Governor
    http: HttpClient
    findings: FindingsStore
    auth: AuthContext
    oast: OastStore
    snapshots: SnapshotStore


def build_context(settings: Settings | None = None) -> AppContext:
    settings = settings or load_settings()
    scope = ScopeManager(enforce=settings.enforce_scope, block_private=settings.block_private)
    for entry in settings.scope:
        scope.add(entry)
    for entry in settings.scope_exclude:
        scope.exclude(entry)
    governor = Governor(rate=settings.rate_limit, max_concurrency=settings.max_concurrency)
    auth = AuthContext()
    http = HttpClient(
        governor,
        user_agent=settings.user_agent,
        default_timeout=settings.timeout,
        connect_guard=scope.blocked_connect_reason,
        auth_provider=auth.merged_headers,
    )
    return AppContext(settings=settings, scope=scope, governor=governor, http=http,
                      findings=FindingsStore(), auth=auth, oast=OastStore.from_env(),
                      snapshots=SnapshotStore(state_dir=os.environ.get("MOONMCP_STATE_DIR")))


def to_dict(obj: object, *, drop_none: bool = True) -> object:
    """Recursively convert dataclasses/containers into JSON-friendly primitives."""

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out = {}
        for f in dataclasses.fields(obj):
            value = to_dict(getattr(obj, f.name), drop_none=drop_none)
            if drop_none and value is None:
                # Drop only None (truly-absent optionals). Empty lists/dicts are
                # kept — "zero open ports" must not be indistinguishable from
                # "field missing".
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
