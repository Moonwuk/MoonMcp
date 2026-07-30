"""Governor / RateLimiter: concurrency cap, rate pacing, and the ordering fix.

The Governor must acquire a rate-limiter token BEFORE a concurrency slot, so a
coroutine waiting for a token does not occupy a slot (which collapsed effective
concurrency below max_concurrency under the old slot-first ordering).
"""

import asyncio
import time

import pytest

from moonmcp.net.ratelimit import Governor, RateLimiter


@pytest.mark.asyncio
async def test_governor_caps_in_flight_concurrency():
    gov = Governor(rate=0, max_concurrency=3)   # rate 0 = unlimited → only the cap gates
    peak = cur = 0

    async def worker():
        nonlocal peak, cur
        async with gov:
            cur += 1
            peak = max(peak, cur)
            await asyncio.sleep(0.02)
            cur -= 1

    await asyncio.gather(*[worker() for _ in range(15)])
    assert peak <= 3


@pytest.mark.asyncio
async def test_governor_waiters_do_not_hold_slots():
    # rate gates hard (1/s, burst 1); concurrency is generous (5). With token-first
    # ordering the 7 coroutines blocked on the TOKEN hold no slot, so free slots stay
    # available. The old slot-first order grabbed all 5 slots up front → _value == 0.
    gov = Governor(rate=1, max_concurrency=5)

    async def worker():
        async with gov:
            await asyncio.sleep(0.01)

    tasks = [asyncio.create_task(worker()) for _ in range(8)]
    await asyncio.sleep(0.2)          # only the single burst token has been issued
    assert gov.semaphore._value >= 4  # most slots still free (waiters aren't holding them)
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_rate_limiter_paces_beyond_the_burst():
    rl = RateLimiter(rate=20)         # capacity defaults to one second's tokens (20)
    start = time.monotonic()
    for _ in range(30):               # 20 free burst + 10 paced at 20/s ≈ 0.5s
        await rl.acquire()
    elapsed = time.monotonic() - start
    assert 0.25 <= elapsed <= 1.5


@pytest.mark.asyncio
async def test_rate_zero_disables_limiting():
    rl = RateLimiter(rate=0)
    start = time.monotonic()
    for _ in range(1000):
        await rl.acquire()
    assert time.monotonic() - start < 0.5
