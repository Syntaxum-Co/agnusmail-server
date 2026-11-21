"""Redis connection pool management and readiness check.

Hard rule: caches and rate-limit buckets must never store plaintext of
user content. Only nonces, identifiers, counters, and ciphertext
references belong in Redis.
"""

from typing import Any

import redis.asyncio as aredis

from agnusmail.core.config import Settings


class RedisClient:
    """Holds the async connection pool shared by the application."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pool: aredis.ConnectionPool | None = None

    def create_pool(self) -> aredis.ConnectionPool:
        self._pool = aredis.ConnectionPool.from_url(
            self._settings.redis_url,
            max_connections=self._settings.redis_pool_max_connections,
            socket_timeout=self._settings.redis_socket_timeout_seconds,
            socket_connect_timeout=self._settings.redis_connect_timeout_seconds,
            health_check_interval=self._settings.redis_health_check_interval_seconds,
        )
        return self._pool

    @property
    def pool(self) -> aredis.ConnectionPool:
        if self._pool is None:
            raise RuntimeError("redis pool not initialized; call create_pool() first")
        return self._pool

    def client(self) -> aredis.Redis:
        return aredis.Redis(connection_pool=self.pool)

    async def dispose(self) -> None:
        if self._pool is not None:
            await self._pool.aclose()
            self._pool = None


async def check_readiness(client: Any) -> bool:
    """Return True when Redis answers PING. Raises on failure."""
    return bool(await client.ping())
