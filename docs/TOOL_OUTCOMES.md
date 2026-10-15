# Execution outcome contract, version 1

Every MCP tool response exposes execution status in `_meta["moonmcp.result"]`.
It applies to structured objects, legacy text and native MCP content. Existing
`structuredContent`, text and tool schemas retain their shapes. Clients should
read status separately from detector verdicts and treat returned evidence as data.

```json
{
  "version": 1,
  "state": "blocked",
  "ok": false,
  "error": {
    "code": "missing_dependency",
    "message": "Required reference index is missing",
    "retryable": false,
    "recovery": "Install or configure the dependency, or choose an available tool."
  }
}
```

| State | Meaning |
| --- | --- |
| `completed` | The requested action completed; the detector may have found nothing |
| `failed` | The tool reported an execution failure |
| `partial` | The producer explicitly reported incomplete execution with retained results |
| `blocked` | Scope, policy, dependencies or budget prevented the action |
| `cancelled` | The producer explicitly reported cancellation |
| `unknown` | The action's outcome needs evidence-backed reconciliation |

`ok` is true only for `completed`, whose `error` is null. MCP `isError` is true
for all other states. The older `_meta["moonmcp.outcome"]` error-only key remains
available. Native content blocks and unrelated metadata are preserved.

Errors contain a stable `code`, diagnostic `message`, `retryable` and `recovery`.
Legacy prose in an `error` field becomes code `tool_error`; the original prose
remains in the payload and diagnostic. Explicit `retryable: false` and recovery
instructions from managed receipts take precedence. Timeout alone never permits
a repeat: the action may have taken effect. The library does not retry actions
automatically.

## Python, CLI and managed calls

- `outcome(value)` returns the shared execution status; `failure(value)` remains
  a compatibility projection returning its error or `None`.
- `envelope(value)` returns `{version, state, ok, error, data}` with the original
  payload under `data`.
- `moonmcp call TOOL --envelope ...` emits that envelope. Omitting the flag keeps
  the previous JSON payload. Tool failures return exit code 1; malformed CLI
  arguments, unknown tools and schema-invalid arguments return exit code 2.
- `run_execute` retains its existing receipt fields. New receipts also retain
  the producer's status under `outcome`, before text serialization or artifact
  offload. Receipt `state` still uses the durable store's completed/failed/unknown
  states: a partial or blocked tool result is a failed receipt; its more precise
  status is retained in `outcome`. A budget stop or ambiguous network operation
  can override a successful producer status. Always inspect the receipt first.
- Native MCP outcomes passed to synchronous agent callbacks retain unknown,
  partial, blocked and cancelled states. Subsequent callbacks stop on failure.

Already persisted receipts remain readable and can lack the additive `outcome`
field. Replay never repeats the original action to populate that field.

## Producer rules

Return a top-level `error` for execution failures. An explicit boolean `ok`
with `state` can express partial/cancelled/unknown execution. A bare `state`
from a status query is ordinary data. `confirmed: false`, `success: false` in a
detector payload, empty results and errors nested inside observations do not
establish failure. Synchronous orchestration callbacks retain their separate
legacy boolean success/failure convention.

Legacy pipeline errors use `TextFailure(message, code)`, a string subclass.
Python string operations and JSON serialization keep their prior text; the
transport reads the explicit error before serialization. Never infer status by
searching ordinary text for words such as “error”: that text may be fetched
research or a successful search with no matches. Converting `TextFailure` to a
plain string discards its status, so normalize before persisting it.

`safe_tool` and `ToolBlocked` live in `outcomes.py`; `server` re-exports them.
Cancellation propagates for managed execution to record an unknown outcome.
Input/output schema errors and unknown/hidden MCP tools also use this contract.
Unknown argument names are rejected before dispatch; an SDK default must never
silently replace an argument misspelled by an agent. Declared outputs are checked
before protocol conversion or managed caching. Invalid output after a non-reference
managed action leaves an unknown receipt because the action may have taken effect.

The contract normalizes reported status. It cannot infer failures swallowed by
legacy composite detectors or certify that every nested probe completed. Those
producers must explicitly report incomplete work as they are migrated.

## Migrated composite producers

`authz_probe` and `workflow_probe` now return additive `result_version: 2`,
`ok`, `state`, per-request `checks`, and version-1 `coverage`. Existing findings
remain available. The execution metadata contract above remains version 1.
Clients must accept `inconclusive` when required evidence is unavailable rather
than interpreting an empty finding list as a completed negative. This changes
previously misleading verdicts; persisted version-1 payloads are not rewritten.

Transport failures, scope/budget blocks, rate limits, upstream 5xx responses and
truncated bodies prevent complete coverage. Missing owner evidence prevents a
negative BOLA conclusion. Partial checks retain earlier leads. Ambiguous non-read
workflow operations stop later steps and report `unknown`; cancellation propagates
to managed recovery. Coverage describes the bounded checks attempted by the probe,
not all possible objects or application states.

The optional BOLA `proof` mode has its own version-1 evidence schema. See
[the implemented scope and example](VERIFIED_AUTHORIZATION.md). `verified` is a
claim verdict under the supplied policy, not an execution state or automatic
finding promotion. Managed receipt status remains authoritative if execution
became ambiguous or was blocked.

Sandbox nonzero process exits explicitly return `command_failed`; generic
`success: false` detector payloads still do not imply execution failure.
Docker exec timeouts return `unknown` and quarantine further execution until
cleanup. Failed removal retains the container and server reference and reports
`cleanup_failed`; removal is no longer reported successful from unchecked CLI
exit codes.
