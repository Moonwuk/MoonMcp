# Persistence and external execution limits

These bounds address selected EX1/EX2 and MS9/MS20 backlog items. They do not
complete the external-tool or memory roadmaps. See the
[current status map](ROADMAP_STATUS_2026-10-21.md) for remaining work.

## Audit retention

Audit JSONL records are serialized under a stable filesystem lock shared by
cooperating writers. Default retention is a 4 MiB active file and three backups.
Environment controls are `MOONMCP_AUDIT_MAX_BYTES`,
`MOONMCP_AUDIT_BACKUPS` and `MOONMCP_AUDIT_FSYNC`. The minimum configured file
limit is 512 bytes; backup counts are bounded to 0–20.

Records exceeding the smaller of the configured file limit and 64 KiB are replaced
by bounded digest metadata, not cut in the middle of JSON. Caller fields cannot
replace the trusted timestamp or event name. Rotation preserves complete legacy
segments, including an already oversized segment from an earlier version; the
first rotation does not retroactively bound that historical file.

Writes and replacement metadata are synchronized to disk when fsync is enabled.
Filesystem support and power-loss behavior still matter. A failed audit write
preserves the in-memory record, emits a warning and appears in the summary; it is
not reported as durable evidence. Only cooperating writers obey the lock.
Process coordination assumes independently initialized processes. Reusing inherited
stores after forking during an active persistence operation is unsupported; use
spawn or exec before accessing persistence in a worker.

## Snapshot baselines

SnapshotStore defaults to 256 named snapshots, 10,000 distinct items per snapshot
and 1,000,000 serialized bytes. Persistent updates use a same-directory private
temporary file, fsync and atomic replacement under the shared directory lock.
A failed replacement preserves the previous baseline. If replacement succeeds
but a later fsync fails, the new file may already be visible; the call reports an
unconfirmed update and the next comparison reloads disk state. Cross-process
comparisons reload the persisted baseline before computing the next difference.
Canonical snapshot names are limited to 120 characters.

Corrupt, oversized or incorrectly typed persisted state raises an explicit error
instead of silently declaring a fresh baseline. Count, item and byte limits also
fail explicitly. Persistent `clear()` removes files as well as the in-memory cache.
Clearing is not a multi-file atomic transaction. This is bounded local persistence,
not a new named-session or distributed coordination service.

## External CLI execution

Known network tools require explicit targets and a scope predicate even through
the direct Python API. Admission is checked before process creation. The MCP
scanner adapter also checks target-like argument values, including inline flags,
and rejects unsupported URI schemes. This validation is not an operating-system
egress boundary and cannot prove arbitrary third-party CLI argument semantics.

The combined stdout/stderr default cap is 1 MiB, configurable up to 16 MiB.
Output is read incrementally; a cap or timeout retains only the bounded prefix and
marks execution incomplete. Partial scanner output is not automatically promoted
to findings after an unsuccessful execution.

The execution deadline includes startup and stdin delivery. Cancellation settles
an owned process-creation task before teardown so a child cannot be lost merely
because its handle arrived after cancellation. Settling process creation can
exceed the requested deadline. Teardown has a separate bounded wait; unconfirmed
cleanup remains visible. POSIX cleanup signals the process group; Windows cleanup
covers the direct child. Escaped descendants and uncooperative runtimes require
stronger isolation.

External scanners remain outside managed request accounting. No binary integrity,
arbitrary target containment, sandbox or production isolation guarantee is added
by these bounds. Tests use synthetic local child processes and injected scanner
results, not external scans.
