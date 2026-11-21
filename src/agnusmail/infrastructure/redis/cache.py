"""Namespaced cache over Redis.

Rule: this cache must never hold plaintext of user content. Only
nonces, identifiers, counters, and opaque references belong here.
"""

from collections.abc import Callable
from typing import Any

from agnusmail.core.constants import CACHE_KEY_PREFIX


class Cache:
    """Async cache with a versioned namespace and mandatory TTLs."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def _key(self, name: str) -> str:
        return f"{CACHE_KEY_PREFIX}v1:{name}"

    async def get(self, name: str) -> str | None:
        value = await self._client.get(self._key(name))
        if value is None:
            return None
        return value if isinstance(value, str) else value.decode("utf-8")

    async def set(self, name: str, value: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        await self._client.set(self._key(name), value, ex=ttl_seconds)

    async def get_or_set(self, name: str, ttl_seconds: int, factory: Callable[[], str]) -> str:
        current = await self.get(name)
        if current is not None:
            return current
        value = factory()
        await self.set(name, value, ttl_seconds)
        return value

    async def delete(self, name: str) -> None:
        await self._client.delete(self._key(name))
