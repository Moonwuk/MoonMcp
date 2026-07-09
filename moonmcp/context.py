"""Shared application context and serialization helpers.

A single :class:`AppContext` bundles the settings, scope manager, rate governor
and HTTP client so every tool draws on the same rate limit and scope state.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass

from .audit import AuditLog, setup_logging
from .auth import AuthContext
from .config import Settings, load_settings
from .findings import FindingsStore
from .intel.oast import OastStore
from .monitor import SnapshotStore
from .net.http import HttpClient
from .net.ratelimit import Governor
from .programs import ProgramStore
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
    audit: AuditLog
    programs: ProgramStore


def build_context(settings: Settings | None = None) -> AppContext:
    settings = settings or load_settings()
    setup_logging()
    scope = ScopeManager(enforce=settings.enforce_scope, block_private=settings.block_private)
    for entry in settings.scope:
        scope.add(entry)
    for entry in settings.scope_exclude:
        scope.exclude(entry)
    governor = Governor(rate=settings.rate_limit, max_concurrency=settings.max_concurrency)
    auth = AuthContext()
    programs = ProgramStore.from_env()
    # If a program was persisted as active, apply its scope so a restart resumes
    # the same engagement rather than an empty scope.
    active = programs.active
    if active is not None:
        for entry in active.scope:
            scope.add(entry)
        for entry in active.scope_exclude:
            scope.exclude(entry)

    def _request_headers() -> dict[str, str]:
        # The active program's bug-bounty header + User-Agent, with engagement
        # credentials layered on top (auth wins on a key collision). Merged into
        # every in-scope request by the HTTP client.
        merged = dict(programs.active_headers())
        merged.update(auth.merged_headers())
        return merged

    http = HttpClient(
        governor,
        user_agent=settings.user_agent,
        default_timeout=settings.timeout,
        connect_guard=scope.blocked_connect_reason,
        auth_provider=_request_headers,
    )
    return AppContext(settings=settings, scope=scope, governor=governor, http=http,
                      findings=FindingsStore(), auth=auth, oast=OastStore.from_env(),
                      snapshots=SnapshotStore(state_dir=os.environ.get("MOONMCP_STATE_DIR")),
                      audit=AuditLog.from_env(), programs=programs)


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
