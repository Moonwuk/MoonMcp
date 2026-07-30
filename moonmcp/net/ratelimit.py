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
        # Acquire the rate-limiter token FIRST, then the concurrency slot, so a slot
        # is held only while a request is actually in flight. The old order (slot then
        # token) let coroutines that were merely WAITING for a token occupy slots,
        # collapsing effective concurrency below max_concurrency whenever the rate
        # gated. If cancelled between the two, a spent token is wasted (not a leak);
        # __aexit__ runs only when __aenter__ returned, so the slot is never
        # double-released.
        await self.limiter.acquire()
        await self.semaphore.acquire()
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.semaphore.release()
