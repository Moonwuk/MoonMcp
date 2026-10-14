"""Shared application context and serialization helpers.

A single :class:`AppContext` bundles the settings, scope manager, rate governor
and HTTP client so every tool draws on the same rate limit and scope state.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditLog, setup_logging
from .auth import AuthContext
from .config import Settings, load_settings
from .findings import FindingsStore
from .flags import FlagStore
from .intel.oast import OastStore
from .intel.oast_server import CallbackServer
from .intercept import HistoryStore
from .memory import MemoryStore
from .monitor import SnapshotStore
from .net.http import HttpClient
from .net.ratelimit import Governor
from .programs import ProgramStore
from .runs import RunStore
from .scope import ScopeManager
from .telemetry.collector import TelemetryCollector


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
    history: HistoryStore
    memory: MemoryStore
    telemetry: TelemetryCollector
    runs: RunStore
    oast_server: CallbackServer | None = None
    flags: FlagStore = field(default_factory=FlagStore)


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
    programs = ProgramStore(state_dir=settings.state_dir or None)
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

    # OPSEC engine: always on — browser-like headers + jitter for every request,
    # even without an active program (stealth is not optional). The BB header
    # itself arrives via auth_provider from the active program; OpsecEngine only
    # adds it too when one was active at build time (dict merge = no duplicate).
    from .opsec import OpsecConfig, OpsecEngine
    opsec_engine = OpsecEngine(OpsecConfig(
        bb_header_name=(active.header_name or "") if active else "",
        bb_header_value=(active.header_value or "") if active else "",
    ))

    # Proxy rule engine: the same singleton the proxy_rules MCP tool drives,
    # so rules registered via proxy_rules(action='add') apply to every request
    # sent through the unified egress (HttpClient).
    from .web.proxy_rules import get_engine as _get_proxy_engine
    proxy_engine = _get_proxy_engine()

    telemetry = TelemetryCollector()
    state_dir = Path(settings.state_dir) if settings.state_dir else None
    if state_dir is not None:
        state_dir.mkdir(parents=True, exist_ok=True)
    memory = MemoryStore(str(state_dir / "memory.db") if state_dir is not None else None)
    http = HttpClient(
        governor,
        user_agent=settings.user_agent,
        default_timeout=settings.timeout,
        connect_pin=scope.resolve_pin,
        auth_provider=_request_headers,
        opsec=opsec_engine,
        proxy_rules=proxy_engine,
        telemetry=telemetry,
    )
    ctx = AppContext(settings=settings, scope=scope, governor=governor, http=http,
                      findings=FindingsStore.from_env(settings.state_dir or None), auth=auth, oast=OastStore.from_env(),
                      snapshots=SnapshotStore(state_dir=settings.state_dir or None),
                      audit=AuditLog.from_env(), programs=programs, history=HistoryStore(),
                      memory=memory, telemetry=telemetry,
                      runs=RunStore.from_env(settings.state_dir or None),
                      flags=FlagStore(memory.db_path))
    from .execution import current_execution

    def _finding_run() -> str | None:
        execution = current_execution()
        return execution.run_id if execution is not None and execution.ctx is ctx else None

    ctx.findings.run_id_provider = _finding_run
    ctx.findings.on_record = lambda finding: telemetry.record_finding(finding.severity, finding.type)
    return ctx


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
