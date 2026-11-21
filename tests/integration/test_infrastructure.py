"""Integration tests against real PostgreSQL and Redis (CI services / docker compose).

Run with: pytest -m integration (requires AGNUSMAIL_DATABASE_URL and AGNUSMAIL_REDIS_URL).
Keys use random identifiers; no database is flushed.
"""

import asyncio
import hashlib
import secrets
from collections.abc import AsyncIterator

import pytest
import redis.asyncio as aredis
from agnusmail.apps.api.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import text

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.redis.rate_limit import RateLimiter
from agnusmail.modules.authentication.stores import NonceStore, SessionStore

pytestmark = pytest.mark.integration


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
async def redis_client(settings: Settings) -> AsyncIterator[aredis.Redis]:
    client = aredis.Redis.from_url(settings.redis_url)
    try:
        yield client
    finally:
        await client.aclose()


def test_database_select_one(settings: Settings) -> None:
    engine = create_db_engine(settings)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar_one() == 1
    finally:
        engine.dispose()


def test_readyz_with_real_dependencies(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


async def test_nonce_consume_is_atomic_under_concurrency(redis_client: aredis.Redis) -> None:
    store = NonceStore(redis_client)
    nonce = await store.create()
    results = await asyncio.gather(*(store.consume(nonce) for _ in range(10)))
    assert results.count(True) == 1


async def test_rate_limiter_sets_ttl_and_blocks(redis_client: aredis.Redis) -> None:
    limiter = RateLimiter(redis_client)
    key = f"it:{secrets.token_hex(8)}"
    assert await limiter.check(key, limit=2, window_seconds=30)
    assert await limiter.check(key, limit=2, window_seconds=30)
    assert not await limiter.check(key, limit=2, window_seconds=30)
    ttl = await redis_client.ttl(f"agnusmail:rl:v1:{key}")
    assert 0 < ttl <= 30


async def test_session_store_lifecycle_and_limit(redis_client: aredis.Redis) -> None:
    store = SessionStore(redis_client, 60, 600, max_sessions_per_owner=2)
    owner = f"0x{secrets.token_hex(20)}"
    tokens = [await store.create(owner, {"address": owner}) for _ in range(3)]
    assert await store.get(tokens[0]) is None
    record = await store.get(tokens[2])
    assert record is not None and record.data == {"address": owner}
    assert await store.renew(tokens[2]) == 60
    await store.revoke(tokens[1])
    await store.revoke(tokens[2])
    assert await redis_client.exists(f"agnusmail:session:v1:owner:{owner}") == 0


def test_siwe_login_end_to_end(settings: Settings) -> None:
    from eth_account import Account

    from tests.unit.test_auth import build_message, sign

    acct = Account.create()
    with TestClient(create_app(settings)) as client:
        nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
        message = build_message(
            acct.address, nonce, domain=settings.siwe_domain, uri=settings.siwe_uri
        )
        response = client.post("/v1/auth/siwe/verify", json=sign(message, acct))
        assert response.status_code == 200, response.text
        session = client.get("/v1/auth/session").json()
    assert session["address"] == acct.address
    assert session["user_id"] == response.json()["user_id"]


async def test_session_fingerprint_update_keeps_ttl(redis_client: aredis.Redis) -> None:
    from agnusmail.modules.authentication.suspicious import fingerprint

    store = SessionStore(redis_client, 60, 600, max_sessions_per_owner=2)
    owner = f"user-{secrets.token_hex(8)}"
    token = await store.create(owner, {}, fingerprint=fingerprint("A", "203.0.113.1"))
    await store.update_fingerprint(token, fingerprint("A", "198.51.100.1"))
    record = await store.get(token)
    assert record is not None
    assert record.fingerprint == fingerprint("A", "198.51.100.1")
    digest = hashlib.sha256(token.encode()).hexdigest()
    ttl = await redis_client.ttl(f"agnusmail:session:v1:data:{digest}")
    assert 0 < ttl <= 60  # KEEPTTL preserved the idle TTL
    await store.revoke(token)
