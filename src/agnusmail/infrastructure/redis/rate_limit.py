"""Fixed-window rate limiter over Redis."""

from typing import Any

from agnusmail.core.constants import RATE_LIMIT_KEY_PREFIX


class RateLimiter:
    """Async fixed-window counter with a versioned namespace.

    INCR and EXPIRE NX run in one MULTI/EXEC transaction, so a counter can never
    be left without a TTL (which would block the key forever).
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    async def check(self, key: str, limit: int, window_seconds: int) -> bool:
        """Increment the counter and allow the request if under the limit."""
        if limit <= 0:
            return False
        name = f"{RATE_LIMIT_KEY_PREFIX}v1:{key}"
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.incr(name)
            pipe.expire(name, window_seconds, nx=True)
            count, _ = await pipe.execute()
        return int(count) <= limit

    async def consume(self, key: str, amount: int, limit: int, window_seconds: int) -> bool:
        """Add ``amount`` to the window's counter; allowed while the total stays within
        ``limit``. A refused request still counts (no free retries against the limit)."""
        if limit <= 0 or amount <= 0 or amount > limit:
            return False
        name = f"{RATE_LIMIT_KEY_PREFIX}v1:{key}"
        async with self._client.pipeline(transaction=True) as pipe:
            pipe.incrby(name, amount)
            pipe.expire(name, window_seconds, nx=True)
            count, _ = await pipe.execute()
        return int(count) <= limit
