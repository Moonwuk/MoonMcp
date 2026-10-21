# Browser observation boundaries

Browser DOM text, HTML, titles, console messages, errors, URLs, storage, cookies
and JavaScript results are untrusted evidence. The additive `trust` and
`content_safety` fields preserve the existing observation payload. Screening is
advisory: it recognizes a bounded set of instruction override, role marker and
secret request patterns in English and Russian. Matches never become
instructions, and a clean or incomplete scan never upgrades trust. The scan
inspects at most 64,000 characters, 512 items and 12 levels; metadata reports
truncation and contains no matched attacker text.

`timeout_ms` bounds each JavaScript evaluation in Python as well as navigation.
The whole operation, including Playwright startup and launch, has a
`wall_timeout_ms` budget (default 60 seconds). Both budgets must be between 1 and
120,000 milliseconds. A call accepts at most 100 interaction actions. Evaluation
timeout stops later actions and extraction. Caller cancellation propagates after
the owned cleanup attempt; repeated cancellation cannot cancel that attempt.

Cleanup has a separate four second reserve, including at most two seconds per
shutdown operation. Python waits do not wait indefinitely for a coroutine which
ignores cancellation. Startup managers and acquisition tasks remain owned even
before a driver or browser handle is returned. Partial startup attempts manager
exit; returned browsers and drivers are closed. Evaluation tasks belong to their
own session; a task still pending after driver shutdown and the reserve makes
that session's cleanup uncertain. Handles arriving after the
cleanup reserve receive a separately retained, bounded disposal attempt.
`cleanup_error` keeps cleanup failures visible alongside an operation error.
`cleanup_confirmed=false` explicitly reports failed or uncertain cleanup and is
never changed to success because a late disposal eventually completes.
`cleanup_confirmed=null` means no browser session was started.

These are Python waiting and observation boundaries. They provide no CPU,
memory, process or network resource isolation, and cannot guarantee that an
unresponsive native process terminates. Browser traffic remains outside managed
HTTP request and byte accounting. Every invocation still creates a fresh browser
context; persistent sessions and stealth policy are separate roadmap work.
