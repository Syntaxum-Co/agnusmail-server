"""Tests for SessionStore: per-owner limit, absolute lifetime, renewal and revocation."""

import hashlib

import pytest

from agnusmail.modules.authentication import stores
from agnusmail.modules.authentication.stores import (
    SESSION_DATA_PREFIX,
    SESSION_OWNER_PREFIX,
    SessionStore,
)
from agnusmail.testing.fakes import FakeAsyncRedis


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def time(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    fake_clock = FakeClock()
    monkeypatch.setattr(stores, "time", fake_clock)
    return fake_clock


def make_store(
    max_sessions: int = 2, idle: int = 60, absolute: int = 600
) -> tuple[SessionStore, FakeAsyncRedis]:
    fake = FakeAsyncRedis()
    return SessionStore(fake, idle, absolute, max_sessions), fake


def data_key(token: str) -> str:
    return SESSION_DATA_PREFIX + hashlib.sha256(token.encode()).hexdigest()


async def test_session_limit_evicts_oldest(clock: FakeClock) -> None:
    store, fake = make_store(max_sessions=2)
    tokens = []
    for _ in range(3):
        tokens.append(await store.create("addr", {}))
        clock.now += 1
    assert await store.get(tokens[0]) is None
    assert await store.get(tokens[1]) is not None
    assert await store.get(tokens[2]) is not None
    assert len(fake.zsets[SESSION_OWNER_PREFIX + "addr"]) == 2


async def test_session_limit_keeps_other_owners(clock: FakeClock) -> None:
    store, _ = make_store(max_sessions=1)
    a = await store.create("addr-a", {})
    b = await store.create("addr-b", {})
    assert await store.get(a) is not None
    assert await store.get(b) is not None


async def test_dead_sessions_do_not_count_toward_limit(clock: FakeClock) -> None:
    store, fake = make_store(max_sessions=2)
    old = await store.create("addr", {})
    clock.now += 1
    dead = await store.create("addr", {})
    fake.expire_now(data_key(dead))  # idle-expired while `old` was renewed
    clock.now += 1
    new = await store.create("addr", {})
    assert await store.get(old) is not None
    assert await store.get(new) is not None


async def test_revoke_removes_owner_index_entry(clock: FakeClock) -> None:
    store, fake = make_store()
    token = await store.create("addr", {})
    await store.revoke(token)
    assert await store.get(token) is None
    assert SESSION_OWNER_PREFIX + "addr" not in fake.zsets


async def test_session_ttls_are_set(clock: FakeClock) -> None:
    store, fake = make_store(idle=60, absolute=600)
    token = await store.create("addr", {"address": "addr"})
    assert fake.ttls[data_key(token)] == 60
    assert fake.ttls[SESSION_OWNER_PREFIX + "addr"] == 600


async def test_renew_slides_idle_ttl(clock: FakeClock) -> None:
    store, fake = make_store(idle=60, absolute=600)
    token = await store.create("addr", {})
    clock.now += 30
    assert await store.renew(token) == 60
    assert fake.ttls[data_key(token)] == 60


async def test_renew_is_capped_by_absolute_lifetime(clock: FakeClock) -> None:
    store, fake = make_store(idle=60, absolute=600)
    token = await store.create("addr", {})
    clock.now += 580
    assert await store.renew(token) == 20
    assert fake.ttls[data_key(token)] == 20


async def test_session_beyond_absolute_lifetime_is_rejected(clock: FakeClock) -> None:
    store, _ = make_store(idle=60, absolute=600)
    token = await store.create("addr", {})
    clock.now += 600
    assert await store.renew(token) is None
    assert await store.get(token) is None


async def test_unknown_and_oversized_tokens_are_rejected(clock: FakeClock) -> None:
    store, _ = make_store()
    assert await store.get("unknown") is None
    assert await store.get("x" * 1000) is None
    assert await store.renew("unknown") is None


def test_store_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError):
        SessionStore(FakeAsyncRedis(), 600, 60, 1)
    with pytest.raises(ValueError):
        SessionStore(FakeAsyncRedis(), 60, 600, 0)
