"""Python deadlines and owned teardown for optional browser observations.

Cooperative deadlines bound Python waits. They are not process resource isolation.
Cleanup uncertainty is reported even when a late handle is eventually disposed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from contextvars import ContextVar
from typing import Any

CLEANUP_STEP_SECONDS = 2.0
CLEANUP_RESERVE_SECONDS = 4.0
_BACKGROUND: set[asyncio.Task[Any]] = set()
_EVALUATIONS: ContextVar[set[asyncio.Task[Any]] | None] = ContextVar(
    "browser_evaluations", default=None)


class BrowserEvaluationTimeout(Exception):
    """The Python wait for JavaScript exceeded its per-evaluation budget."""


class BrowserWallTimeout(Exception):
    """The complete browser operation exceeded its Python wall budget."""


def _consume(task: asyncio.Task[Any]) -> None:
    if not task.cancelled():
        task.exception()


def _retain(task: asyncio.Task[Any]) -> None:
    _BACKGROUND.add(task)

    def finished(done: asyncio.Task[Any]) -> None:
        _BACKGROUND.discard(done)
        _consume(done)

    task.add_done_callback(finished)


def _value(task: asyncio.Task[Any] | None) -> Any:
    if task is None or not task.done() or task.cancelled():
        return None
    try:
        return task.result()
    except Exception:
        return None


async def _close(close: Callable[[], Coroutine[Any, Any, Any]], deadline: float) -> bool:
    """Never wait for a cancellation-resistant close coroutine past the reserve."""
    remaining = min(CLEANUP_STEP_SECONDS, max(0.0, deadline - asyncio.get_running_loop().time()))
    if remaining <= 0:
        return False
    try:
        task = asyncio.create_task(close())
    except Exception:
        return False
    done, _ = await asyncio.wait({task}, timeout=remaining)
    if not done:
        task.cancel()
        _retain(task)
        return False
    try:
        task.result()
        return True
    except (Exception, asyncio.CancelledError):
        return False


def _dispose_late(task: asyncio.Task[Any], method: str) -> None:
    """Keep ownership after the caller's bounded cleanup reserve expires."""
    def finished(done: asyncio.Task[Any]) -> None:
        handle = _value(done)
        if handle is not None:
            async def dispose() -> None:
                deadline = asyncio.get_running_loop().time() + CLEANUP_STEP_SECONDS
                await _close(getattr(handle, method), deadline)
            _retain(asyncio.create_task(dispose()))

    task.add_done_callback(finished)
    _retain(task)


async def evaluate(page: Any, script: str, timeout_ms: int) -> Any:
    task = asyncio.create_task(page.evaluate(script))
    evaluations = _EVALUATIONS.get()
    if evaluations is not None:
        evaluations.add(task)
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout_ms / 1000)
    except asyncio.CancelledError:
        task.cancel()
        _retain(task)
        raise
    if not done:
        task.cancel()
        _retain(task)
        raise BrowserEvaluationTimeout(f"JavaScript exceeded {timeout_ms} ms")
    return task.result()


class _OwnedSession:
    def __init__(self) -> None:
        self.manager: Any = None
        self.playwright: Any = None
        self.browser: Any = None
        self.start: asyncio.Task[Any] | None = None
        self.launch: asyncio.Task[Any] | None = None
        self.evaluations: set[asyncio.Task[Any]] = set()

    async def work(self, factory: Callable[[], Any], launch_kwargs: dict,
                   operation: Callable[[Any], Awaitable[None]]) -> None:
        # Acquisition belongs to us before any await; cancellation cannot lose a handle.
        self.manager = factory()
        self.start = asyncio.create_task(self.manager.start())
        self.playwright = await asyncio.shield(self.start)
        self.launch = asyncio.create_task(self.playwright.chromium.launch(**launch_kwargs))
        self.browser = await asyncio.shield(self.launch)
        token = _EVALUATIONS.set(self.evaluations)
        try:
            await operation(self.browser)
        finally:
            _EVALUATIONS.reset(token)

    async def cleanup(self, work: asyncio.Task[Any]) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + CLEANUP_RESERVE_SECONDS
        work.cancel()
        acquisitions = [task for task in (self.start, self.launch) if task is not None]
        for task in acquisitions:
            if not task.done():
                task.cancel()
        # Let cooperative cancellation run, then settle late acquisitions for at
        # most half the reserve before selecting the exact handles to close.
        await asyncio.sleep(0)
        pending = {task for task in acquisitions if not task.done()}
        if pending:
            await asyncio.wait(pending, timeout=min(
                CLEANUP_RESERVE_SECONDS / 2, max(0.0, deadline - loop.time())))
        playwright = self.playwright or _value(self.start)
        browser = self.browser or _value(self.launch)
        closed = browser is None
        if browser is not None:
            # Reserve time to stop the driver even when browser.close stalls.
            close_deadline = min(deadline, loop.time() + max(0.0, deadline - loop.time()) / 2)
            closed = await _close(browser.close, close_deadline)
        stopped = False
        if playwright is not None:
            stopped = await _close(playwright.stop, deadline)
        elif self.manager is not None:
            exit_manager = getattr(self.manager, "__aexit__", None)
            if exit_manager is not None:
                # A partial start may already own a driver without returning it.
                await _close(lambda: exit_manager(None, None, None), deadline)
        # Handles which appear only after our selection remain owned. A separate
        # bounded late disposer attempts their shutdown, but cannot certify this run.
        late = False
        for acquisition, method in ((self.start, "stop"), (self.launch, "close")):
            if acquisition is not None:
                if not acquisition.done():
                    late = True
                    _dispose_late(acquisition, method)
                else:
                    handle = _value(acquisition)
                    selected = playwright if method == "stop" else browser
                    if handle is not None and handle is not selected:
                        late = True
                        _dispose_late(acquisition, method)
                    else:
                        _consume(acquisition)
        pending_evaluations = {task for task in self.evaluations if not task.done()}
        for task in pending_evaluations:
            task.cancel()
        if pending_evaluations:
            await asyncio.wait(pending_evaluations, timeout=max(0.0, deadline - loop.time()))
        evaluations_settled = all(task.done() for task in self.evaluations)
        for task in self.evaluations:
            if task.done():
                _consume(task)
            else:
                _retain(task)
        await asyncio.sleep(0)
        if not work.done():
            _retain(work)
        else:
            _consume(work)
        acquired = playwright is not None and browser is not None
        return acquired and closed and stopped and work.done() and not late and evaluations_settled


async def run_session(result: Any, factory: Callable[[], Any], launch_kwargs: dict,
                      operation: Callable[[Any], Awaitable[None]], wall_timeout_ms: int) -> None:
    session = _OwnedSession()
    result.cleanup_confirmed = False
    work = asyncio.create_task(session.work(factory, launch_kwargs, operation))
    interrupted = False
    error: Exception | None = None
    try:
        done, _ = await asyncio.wait({work}, timeout=wall_timeout_ms / 1000)
        if not done:
            error = BrowserWallTimeout(f"Browser operation exceeded {wall_timeout_ms} ms")
        else:
            work.result()
    except asyncio.CancelledError:
        interrupted = True
    except Exception as exc:
        error = exc
    finally:
        cleanup = asyncio.create_task(session.cleanup(work))
        # Repeated caller cancellation must never cancel the owned cleanup task.
        while True:
            try:
                result.cleanup_confirmed = await asyncio.shield(cleanup)
                break
            except asyncio.CancelledError:
                interrupted = True
                if cleanup.done() and cleanup.cancelled():
                    result.cleanup_confirmed = False
                    break
            except Exception as exc:
                result.cleanup_confirmed = False
                result.cleanup_error = f"Browser cleanup failed: {type(exc).__name__}: {exc}"[:400]
                result.error = result.error or result.cleanup_error
                break
        if not result.cleanup_confirmed:
            result.cleanup_error = (getattr(result, "cleanup_error", None)
                                    or "Browser cleanup could not be confirmed")
            result.error = result.error or result.cleanup_error
    if interrupted:
        raise asyncio.CancelledError
    if error is not None:
        raise error
