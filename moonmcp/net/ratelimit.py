"""A tiny asyncio token-bucket rate limiter + concurrency gate.

Shared across all outbound traffic so that MoonMCP never accidentally hammers a
target harder than its configured budget allows.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Token bucket: at most ``rate`` acquisitions per second on average.

    A ``rate`` of 0 (or less) disables limiting entirely.  ``capacity`` controls
    how large a burst may be; it defaults to one second's worth of tokens.
    """

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = max(0.0, rate)
        self.capacity = capacity if capacity is not None else max(1.0, self.rate)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Sleep just long enough for one more token to accrue.
                await asyncio.sleep((1.0 - self._tokens) / self.rate)


class Governor:
    """Combines a :class:`RateLimiter` with a concurrency semaphore."""

    def __init__(self, rate: float, max_concurrency: int) -> None:
        self.limiter = RateLimiter(rate)
        self.semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def __aenter__(self) -> Governor:
        await self.semaphore.acquire()
        try:
            await self.limiter.acquire()
        except BaseException:
            self.semaphore.release()
            raise
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.semaphore.release()
