"""Durable, run-bound dispatch through the already-authorised tool registry.

The dispatcher never imports a tool by name or unwraps its gates. A receipt is
reserved before execution, and every HttpClient send reserves its own budget.
Unknown outcomes are deliberately not retried: an interrupted worker may have
already caused a remote side effect. Direct typed tools remain compatible.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import inspect
import ipaddress
import json
import time
from collections import OrderedDict
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from pydantic import ValidationError

from . import __version__, sdk
from .memory import normalize_target
from .outcomes import failure

# Derived views preserve existing import contracts; policies live in registry.py.
from .registry import POLICIES, policy, request_accounting

PURE_REFERENCE_TOOLS = frozenset(p.name for p in POLICIES.values() if p.static_reference)
METERED_HTTP_TOOLS = frozenset(p.name for p in POLICIES.values() if p.accounting == "http_client")
LOCAL_TOOLS = frozenset(p.name for p in POLICIES.values() if p.accounting == "local")
PUBLIC_RESEARCH_TOOLS = frozenset(p.name for p in POLICIES.values() if p.public_research)


def target_in_run(target: str, run_target: str) -> bool:
    """Match an exact canonical host, explicit subdomain wildcard, or IP CIDR.

    A wildcard excludes its apex, matching existing scope wildcard semantics.
    Ordinary host runs never implicitly authorize subdomains.
    """
    host = normalize_target(target)
    if run_target.startswith("*."):
        apex = normalize_target(run_target[2:])
        return host.endswith("." + apex)
    if "/" in run_target and "://" not in run_target:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(run_target, strict=False)
        except ValueError:
            return False
    return host == normalize_target(run_target)


class ExecutionBlocked(ValueError):
    """A dispatch refusal with a stable protocol error code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


def _blocked(exc: ValueError) -> ExecutionBlocked:
    detail = str(exc)
    if "budget" in detail:
        code = "budget_exhausted"
    elif "paused" in detail:
        code = "run_paused"
    elif "cancelled" in detail:
        code = "run_cancelled"
    else:
        code = "execution_blocked"
    return ExecutionBlocked(code, detail)


@dataclass
class ExecutionScope:
    """Context propagated to nested coroutines and asyncio.to_thread workers."""

    ctx: Any
    run_id: str
    invocation_id: str
    requests: int = 0
    ambiguous: bool = False
    blocked_code: str | None = None
    context_hash: str = ""
    tool_name: str = ""
    target: str = ""

    def before_request(self, url: str) -> None:
        if request_accounting(self.tool_name) != "http_client":
            self.blocked_code = "execution_unmetered"
            raise ExecutionBlocked(self.blocked_code, "local tools may not send HTTP requests")
        if self.tool_name not in PUBLIC_RESEARCH_TOOLS and not target_in_run(url, self.target):
            self.blocked_code = "run_target_mismatch"
            raise ExecutionBlocked(self.blocked_code, "request target is outside this run's target")
        if self.context_hash and self.context_hash != _digest(_context_state(self.ctx)):
            self.blocked_code = "execution_context_changed"
            raise ExecutionBlocked(self.blocked_code,
                                   "scope/auth configuration changed during execution")
        try:
            self.ctx.runs.consume_invocation_request(self.invocation_id)
        except ValueError as exc:
            error = _blocked(exc)
            self.blocked_code = error.code
            raise error from exc
        self.requests += 1


_CURRENT: ContextVar[ExecutionScope | None] = ContextVar("moonmcp_execution", default=None)


def current_execution() -> ExecutionScope | None:
    return _CURRENT.get()


class ResultCache:
    """Bounded, session-only TTL cache; values are copied across callers."""

    def __init__(self, *, max_entries: int = 128, ttl: float = 60.0,
                 max_bytes: int = 2_000_000) -> None:
        self.max_entries = max(0, max_entries)
        self.ttl = max(0.0, ttl)
        self.max_bytes = max(0, max_bytes)
        self._items: OrderedDict[str, tuple[float, Any, int]] = OrderedDict()
        self._bytes = 0

    def get(self, key: str) -> tuple[bool, Any]:
        entry = self._items.get(key)
        if entry is None:
            return False, None
        deadline, value, size = entry
        if time.monotonic() >= deadline:
            del self._items[key]
            self._bytes -= size
            return False, None
        self._items.move_to_end(key)
        return True, copy.deepcopy(value)

    def put(self, key: str, value: Any) -> None:
        size = len(json.dumps(value, ensure_ascii=False).encode())
        if not self.max_entries or not self.ttl or size > self.max_bytes:
            return
        prior = self._items.pop(key, None)
        if prior:
            self._bytes -= prior[2]
        self._items[key] = (time.monotonic() + self.ttl, copy.deepcopy(value), size)
        self._bytes += size
        while len(self._items) > self.max_entries or self._bytes > self.max_bytes:
            _, (_, _, removed) = self._items.popitem(last=False)
            self._bytes -= removed


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _cache_key(ctx: Any, run_id: str, name: str, arguments: dict, tool: Any) -> str:
    # Credentials never appear in keys/receipts/logs; a changed scope/auth/profile
    # invalidates prior entries even for these target-independent references.
    return _digest({
        "run": run_id, "name": name, "arguments": arguments, "version": __version__,
        "callable": id(tool.fn), "schema": tool.parameters,
        "context": _context_state(ctx),
    })


def _context_state(ctx: Any) -> dict:
    program_store = getattr(ctx, "programs", None)
    active = getattr(program_store, "active", None)
    headers = dict(program_store.active_headers()) if program_store is not None else {}
    headers.update(ctx.auth.merged_headers())
    http = getattr(ctx, "http", None)
    opsec_config = getattr(getattr(http, "_opsec", None), "config", None)
    rule_engine = getattr(http, "_proxy_rules", None)
    rules = (rule_engine.list_rules()
             if rule_engine is not None and hasattr(rule_engine, "list_rules") else [])
    if any(rule.enabled and rule.token_provider is not None for rule in rules):
        raise ExecutionBlocked("execution_context_unverifiable",
                               "dynamic proxy credentials cannot be pinned to this run")
    return {
        "auth": headers, "program": getattr(active, "name", None),
        "opsec": (asdict(opsec_config)
                  if is_dataclass(opsec_config) and not isinstance(opsec_config, type) else None),
        "proxy_rules": [rule.to_dict() for rule in rules], "scope": ctx.scope.entries(),
        "scope_enforced": ctx.settings.enforce_scope,
        "private_blocked": ctx.settings.block_private,
        "intrusive": ctx.settings.allow_intrusive,
    }


def _jsonable(result: Any) -> Any:
    if hasattr(result, "model_dump"):
        result = result.model_dump(mode="json", exclude_none=True)
    # Check serializability before recording completion or caching. Do not use
    # repr/default=str, which can silently turn unsupported outputs into success.
    json.dumps(result, allow_nan=False)
    return result


def compact_result(ctx: Any, result: dict, max_chars: int = 6000) -> dict:
    """Offload a large data field losslessly; keep execution errors top-level.

    Every UTF-8 chunk is below the artifact store's 1 MB cap. Receipts retain a
    manifest rather than storing another full copy; replay reuses these IDs.
    Preview text is untrusted evidence, not instructions or a confirmed finding.
    """
    if "data" not in result or "output_manifest" in result:
        return result
    max_chars = max(256, min(int(max_chars), 20_000))
    encoded = json.dumps(result["data"], ensure_ascii=False, allow_nan=False)
    if len(encoded) <= max_chars:
        return result
    chunks = []
    for index, offset in enumerate(range(0, len(encoded), 200_000)):
        artifact = ctx.runs.add_artifact(
            result["run_id"], "tool_output", f"{result['invocation_id']}:{index}",
            encoded[offset:offset + 200_000],
        )
        chunks.append({"id": artifact["id"], "sha256": artifact["sha256"],
                       "bytes": artifact["size"]})
    raw = encoded.encode()
    return {**result, "data": {"preview": encoded[:max_chars // 2],
                              "preview_truncated": True, "trust": "untrusted"},
            "output_manifest": {"format": "json", "encoding": "utf-8", "bytes": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest(), "chunks": chunks,
                                "complete": True,
                                "retrieval": "Read chunks in order with run_artifact_read; "
                                             "concatenate content and decode JSON, or request "
                                             "result_mode=full with the same idempotency key."}}


def expand_result(ctx: Any, result: dict) -> dict:
    """Recover full output from a receipt's run-owned, digest-verified artifacts."""
    manifest = result.get("output_manifest")
    if manifest is None:
        return result
    content = []
    for chunk in manifest["chunks"]:
        artifact = ctx.runs.get_artifact(result["run_id"], chunk["id"])
        raw = artifact["content"].encode()
        if len(raw) != chunk["bytes"] or hashlib.sha256(raw).hexdigest() != chunk["sha256"]:
            raise ValueError("tool output artifact integrity check failed")
        content.append(artifact["content"])
    text = "".join(content)
    raw = text.encode()
    if len(raw) != manifest["bytes"] or hashlib.sha256(raw).hexdigest() != manifest["sha256"]:
        raise ValueError("tool output manifest integrity check failed")
    return {**result, "data": json.loads(text)}


def _persist(ctx: Any, invocation_id: str, state: str, result: dict) -> dict:
    """A failed receipt write never means the remote action did not happen."""
    try:
        result = compact_result(ctx, result)
        ctx.runs.finish_invocation(invocation_id, state, result)
    except Exception:
        # The durable running receipt is retained, so reuse of the same key
        # cannot repeat the action even if the outcome could not be saved.
        return {"ok": False, "run_id": result["run_id"], "invocation_id": invocation_id,
                "state": "unknown", "error": "receipt_write_failed", "retryable": False,
                "receipt_persisted": False, "requests": result.get("requests", 0),
                "recovery": "Reconcile the existing receipt; do not repeat the action."}
    return result


async def _invoke(ctx: Any, tool: Any, arguments: dict,
                  invocation_id: str, timeout_seconds: float | None) -> Any:
    async def call() -> Any:
        result = tool.fn(**arguments)
        return await result if inspect.isawaitable(result) else result

    task = asyncio.create_task(call())
    started = time.monotonic()
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=0.1)
            if done:
                return task.result()
            if timeout_seconds is not None and time.monotonic() - started >= timeout_seconds:
                raise TimeoutError("tool execution timed out; reconcile the invocation receipt")
            try:
                ctx.runs.check_invocation(invocation_id)
            except ValueError as exc:
                raise _blocked(exc) from exc
    finally:
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


async def execute_tool(ctx: Any, registry: Mapping[str, Any], run_id: str,
                       tool_name: str, arguments: dict[str, Any], *,
                       task_id: int | None = None, idempotency_key: str | None = None,
                       owner: str | None = None, timeout_seconds: float | None = None,
                       claim_token: str | None = None,
                       availability: Mapping[str, Any] | None = None,
                       result_mode: str = "summary") -> dict:
    """Execute a live allowed Tool object and persist its outcome exactly once.

    ``registry`` must contain only the effective profile's allowed, gated Tool
    objects. A compact host may hide their schemas while retaining that logical
    allowlist. Never pass the unfiltered module globals. Existing receipts are
    replayed only after the same profile/capability/argument checks succeed.
    """
    if _CURRENT.get() is not None:
        raise ExecutionBlocked("recursive_execution", "nested run execution is not supported")
    if result_mode not in {"summary", "full"}:
        raise ValueError("result_mode must be summary or full")
    if policy(tool_name).execution_control or tool_name.startswith("run_"):
        raise ExecutionBlocked("execution_control", "use control tools directly, outside run_execute")
    tool = registry.get(tool_name)
    if tool is None:
        raise ExecutionBlocked("tool_unavailable", "tool is not exposed by the effective profile")
    if request_accounting(tool_name) == "unmetered":
        raise ExecutionBlocked(
            "execution_unmetered",
            "This tool's transport has not been verified for hard request accounting. "
            "Use a metered alternative or its direct typed interface outside this managed run.",
        )
    if timeout_seconds is not None and (timeout_seconds <= 0 or timeout_seconds > 3600):
        raise ValueError("timeout_seconds must be greater than zero and at most 3600")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    allowed = set(tool.parameters.get("properties", {}))
    if set(arguments) - allowed:
        raise ValueError("unknown tool arguments: " + ", ".join(sorted(set(arguments) - allowed)))
    try:
        validated, canonical_arguments = sdk.validate_arguments(tool, arguments)
    except ValidationError as exc:
        # ValidationError text can contain input credentials; expose field names only.
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
        raise ValueError("invalid tool arguments: " + ", ".join(fields)) from None
    if tool_name == "triage_findings" and validated.get("apply"):
        raise ExecutionBlocked("execution_control", "global findings mutation must run outside run_execute")
    if tool_name == "label_finding":
        owned_ids = {finding.id for finding in ctx.findings.list(run_id=run_id)}
        if validated.get("finding_id") not in owned_ids:
            raise ExecutionBlocked("run_target_mismatch", "finding must belong to the executing run")
    if sdk.requires_context(tool):
        raise ExecutionBlocked("tool_unavailable", "tool requires a direct MCP session context")
    intrusive = bool(getattr(tool.fn, "__moonmcp_intrusive__", False))
    if tool_name == "waf_detect" and ctx.settings.allow_intrusive:
        intrusive = True  # its existing implementation enables active checks dynamically
    if intrusive and not ctx.settings.allow_intrusive:
        raise ExecutionBlocked("disabled", "intrusive tools are disabled")
    if availability is not None:
        status = availability.get(tool_name)
        if status is not None and not status.get("available", True):
            reasons = status.get("reasons", [])
            raise ExecutionBlocked("missing_dependency", "; ".join(
                str(reason.get("reason", reason)) if isinstance(reason, dict) else str(reason)
                for reason in reasons
            ))
    context_state = _context_state(ctx)
    argument_hash = _digest({"arguments": canonical_arguments, "context": context_state,
                             "schema": tool.parameters, "version": __version__})
    run_target = ctx.runs.get(run_id)["target"]
    if tool_name in METERED_HTTP_TOOLS or tool_name in {"add_finding", "promote_lead"}:
        # Third-party research URLs are intentional; target-bound enumeration
        # still has to describe this run's domain. Self-scoped/raw requests also
        # meet the same check at HttpClient's dispatch boundary below.
        target_fields = ("domain",) if tool_name in PUBLIC_RESEARCH_TOOLS else (
            "target", "targets", "url", "domain", "endpoint",
        )
        for field in target_fields:
            values = validated.get(field)
            values = values if isinstance(values, list) else [values]
            if any(isinstance(value, str) and value and not target_in_run(value, run_target)
                   for value in values):
                raise ExecutionBlocked("run_target_mismatch",
                                       "tool target is outside this run's target")
    try:
        record = ctx.runs.begin_invocation(
            run_id, tool_name, argument_hash, task_id=task_id,
            idempotency_key=idempotency_key, intrusive=intrusive, owner=owner,
            claim_token=claim_token,
        )
    except ValueError as exc:
        raise _blocked(exc) from exc
    invocation_id = record["id"]
    if not record["created"]:
        result = record.get("result")
        if result:
            if result_mode == "full":
                result = expand_result(ctx, result)
            replay = {**result, "replayed": True}
            if record.get("resolution") is not None:
                replay["resolution"] = record["resolution"]
            return replay
        replay = {"ok": False, "run_id": run_id, "invocation_id": invocation_id,
                  "state": record["state"],
                  "error": "outcome_unknown" if record["state"] == "unknown" else "execution_in_progress",
                  "retryable": False, "replayed": True,
                  "recovery": "Inspect the existing receipt; do not repeat an unfinished action."}
        if record.get("resolution") is not None:
            replay["resolution"] = record["resolution"]
        return replay

    scope = ExecutionScope(ctx, run_id, invocation_id, context_hash=_digest(context_state),
                           tool_name=tool_name, target=run_target)
    token = _CURRENT.set(scope)
    cache: ResultCache | None = None
    key = ""
    cached = False
    dispatched = False
    try:
        ctx.runs.check_invocation(invocation_id)
        if tool_name in PURE_REFERENCE_TOOLS:
            cache = getattr(ctx, "_execution_cache", None)
            if cache is None:
                cache = ResultCache()
                ctx._execution_cache = cache
            key = _cache_key(ctx, run_id, tool_name, canonical_arguments, tool)
            cached, value = cache.get(key)
        if not cached:
            dispatched = True
            value = await _invoke(ctx, tool, validated, invocation_id, timeout_seconds)
        err = failure(value)
        if err is not None and err.code == "internal_error" and tool_name not in PURE_REFERENCE_TOOLS:
            scope.ambiguous = True
        value = _jsonable(value)
        state = "unknown" if scope.ambiguous else "failed" if err or scope.blocked_code else "completed"
        result = {"ok": state == "completed", "run_id": run_id,
                  "invocation_id": invocation_id, "state": state, "data": value,
                  "cached": cached, "requests": scope.requests}
        if scope.ambiguous:
            result.update(error="outcome_unknown", retryable=False,
                          recovery="Reconcile evidence before issuing another action.")
        elif scope.blocked_code:
            result.update(error=scope.blocked_code, retryable=False,
                          recovery="Stop this action and inspect the run state and budget.")
        elif err:
            result.update(error=err.code, retryable=False, recovery=err.recovery)
        result = _persist(ctx, invocation_id, state, result)
        if result["ok"] and cache is not None and not cached:
            cache.put(key, value)
        if result_mode == "full":
            result = expand_result(ctx, result)
        return result
    except asyncio.CancelledError:
        _persist(ctx, invocation_id, "unknown", {
            "ok": False, "run_id": run_id, "invocation_id": invocation_id,
            "state": "unknown", "error": "outcome_unknown", "retryable": False,
            "requests": scope.requests,
            "recovery": "Execution was interrupted; reconcile before issuing another action.",
        })
        raise
    except Exception as exc:
        unknown = (isinstance(exc, TimeoutError) or scope.ambiguous
                   or (dispatched and tool_name not in PURE_REFERENCE_TOOLS
                       and not isinstance(exc, ExecutionBlocked)))
        if isinstance(exc, ExecutionBlocked) and exc.code in {"run_paused", "run_cancelled"}:
            unknown = True
        state = "unknown" if unknown else "failed"
        code = ("outcome_unknown" if unknown else getattr(exc, "code", "internal_error"))
        result = {"ok": False, "run_id": run_id, "invocation_id": invocation_id,
                  "state": state, "error": code, "retryable": False,
                  "requests": scope.requests,
                  "recovery": "Inspect this receipt and its evidence before another action."}
        return _persist(ctx, invocation_id, state, result)
    finally:
        _CURRENT.reset(token)
