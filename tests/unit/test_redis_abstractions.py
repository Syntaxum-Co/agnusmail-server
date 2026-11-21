"""Unit tests for cache and rate limiter abstractions using a fake Redis."""

import pytest

from agnusmail.infrastructure.redis.cache import Cache
from agnusmail.infrastructure.redis.rate_limit import RateLimiter
from agnusmail.modules.authentication.stores import NonceStore
from tests.unit.fakes import FakeAsyncRedis


async def test_cache_set_get_roundtrip() -> None:
    fake = FakeAsyncRedis()
    cache = Cache(fake)
    await cache.set("device:1", "opaque-ref", ttl_seconds=60)
    assert await cache.get("device:1") == "opaque-ref"
    key = next(iter(fake.store))
    assert key.startswith("agnusmail:cache:")
    assert fake.ttls[key] == 60


async def test_cache_rejects_non_positive_ttl() -> None:
    with pytest.raises(ValueError):
        await Cache(FakeAsyncRedis()).set("k", "v", ttl_seconds=0)


async def test_cache_delete_removes_entry() -> None:
    cache = Cache(FakeAsyncRedis())
    await cache.set("k", "v", ttl_seconds=10)
    await cache.delete("k")
    assert await cache.get("k") is None


async def test_rate_limiter_allows_under_limit() -> None:
    limiter = RateLimiter(FakeAsyncRedis())
    results = [await limiter.check("ip:1", limit=3, window_seconds=60) for _ in range(3)]
    assert all(results)


async def test_rate_limiter_blocks_over_limit() -> None:
    limiter = RateLimiter(FakeAsyncRedis())
    for _ in range(3):
        await limiter.check("ip:2", limit=3, window_seconds=60)
    assert await limiter.check("ip:2", limit=3, window_seconds=60) is False


async def test_rate_limiter_sets_ttl_once_per_window() -> None:
    fake = FakeAsyncRedis()
    limiter = RateLimiter(fake)
    await limiter.check("ip:3", limit=5, window_seconds=60)
    key = next(iter(fake.store))
    assert fake.ttls[key] == 60
    fake.ttls[key] = 10  # window partially elapsed
    await limiter.check("ip:3", limit=5, window_seconds=60)
    assert fake.ttls[key] == 10  # EXPIRE NX does not extend the window


async def test_rate_limiter_different_keys_isolated() -> None:
    limiter = RateLimiter(FakeAsyncRedis())
    assert await limiter.check("a", limit=1, window_seconds=60) is True
    assert await limiter.check("b", limit=1, window_seconds=60) is True


async def test_rate_limiter_zero_limit_blocks_immediately() -> None:
    assert await RateLimiter(FakeAsyncRedis()).check("x", limit=0, window_seconds=60) is False


async def test_nonce_is_single_use_and_expires() -> None:
    fake = FakeAsyncRedis()
    store = NonceStore(fake)
    nonce = await store.create()
    assert fake.ttls[next(iter(fake.store))] == 300
    assert await store.consume(nonce) is True
    assert await store.consume(nonce) is False
