"""Shared in-memory test doubles and factories (no network)."""

from typing import Any

from apps.api.main import create_app
from fastapi import FastAPI
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.base import Base
from agnusmail.modules import models as _all_models  # noqa: F401  (registers every table)

BASE_VALUES: dict[str, Any] = {
    "database_url": "postgresql+psycopg://user:pass@localhost:5432/agnusmail",
    "redis_url": "redis://localhost:6379/0",
}


def make_settings(**overrides: Any) -> Settings:
    return Settings.model_validate({**BASE_VALUES, **overrides})


class FakeAsyncRedis:
    """Minimal stand-in for redis.asyncio.Redis covering the commands the app uses.

    TTLs are recorded, not enforced; tests call ``expire_now`` to simulate expiry.
    """

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.ttls: dict[str, int] = {}
        self.fail = False

    def _guard(self) -> None:
        if self.fail:
            raise ConnectionError("fake redis down")

    def expire_now(self, key: str) -> None:
        self.store.pop(key, None)
        self.zsets.pop(key, None)
        self.ttls.pop(key, None)

    async def ping(self) -> bool:
        self._guard()
        return True

    async def get(self, key: str) -> str | None:
        self._guard()
        return self.store.get(key)

    async def set(
        self,
        key: str,
        value: str,
        ex: int | None = None,
        keepttl: bool = False,
        xx: bool = False,
    ) -> bool | None:
        self._guard()
        if xx and key not in self.store:
            return None
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex
        elif not keepttl:
            self.ttls.pop(key, None)
        return True

    async def delete(self, *keys: str) -> int:
        self._guard()
        removed = 0
        for key in keys:
            if key in self.store or key in self.zsets:
                removed += 1
            self.expire_now(key)
        return removed

    async def exists(self, key: str) -> int:
        self._guard()
        return int(key in self.store or key in self.zsets)

    async def expire(self, key: str, seconds: int, nx: bool = False) -> bool:
        self._guard()
        if key not in self.store and key not in self.zsets:
            return False
        if nx and key in self.ttls:
            return False
        self.ttls[key] = seconds
        return True

    async def incr(self, key: str) -> int:
        self._guard()
        current = int(self.store.get(key, "0")) + 1
        self.store[key] = str(current)
        return current

    async def incrby(self, key: str, amount: int) -> int:
        self._guard()
        current = int(self.store.get(key, "0")) + amount
        self.store[key] = str(current)
        return current

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        self._guard()
        zset = self.zsets.setdefault(key, {})
        added = sum(1 for member in mapping if member not in zset)
        zset.update(mapping)
        return added

    async def zrange(self, key: str, start: int, end: int) -> list[str]:
        self._guard()
        members = sorted(self.zsets.get(key, {}).items(), key=lambda item: item[1])
        ordered = [member for member, _ in members]
        return ordered[start:] if end == -1 else ordered[start : end + 1]

    async def zrem(self, key: str, *members: str) -> int:
        self._guard()
        zset = self.zsets.get(key, {})
        removed = sum(1 for member in members if zset.pop(member, None) is not None)
        if key in self.zsets and not zset:
            self.expire_now(key)
        return removed

    def pipeline(self, transaction: bool = True) -> "FakePipeline":
        return FakePipeline(self)


class FakePipeline:
    """Queues commands and runs them sequentially on execute (single-threaded fake)."""

    def __init__(self, redis: FakeAsyncRedis) -> None:
        self._redis = redis
        self._calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    async def __aenter__(self) -> "FakePipeline":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        self._calls.clear()

    def __getattr__(self, name: str) -> Any:
        def queue(*args: Any, **kwargs: Any) -> "FakePipeline":
            self._calls.append((name, args, kwargs))
            return self

        return queue

    async def execute(self) -> list[Any]:
        results = [
            await getattr(self._redis, name)(*args, **kwargs) for name, args, kwargs in self._calls
        ]
        self._calls.clear()
        return results


CREATED_ENGINES: list[Engine] = []


def dispose_test_engines() -> None:
    while CREATED_ENGINES:
        CREATED_ENGINES.pop().dispose()


def make_session_factory() -> sessionmaker[Session]:
    """In-memory SQLite with the ORM schema; one shared connection across threads.

    Engines are disposed after each test by the autouse fixture in conftest.py.
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        # SQLite ignores foreign keys unless enabled per connection.
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    CREATED_ENGINES.append(engine)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


class FakeObjectStorage:
    """In-memory S3 stand-in. ``objects`` is what a client uploaded with the URL."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.deleted: list[str] = []

    def presign_upload(self, key: str, size: int, ttl_seconds: int) -> str:
        return f"https://storage.test/put/{key}?size={size}&ttl={ttl_seconds}"

    def presign_download(self, key: str, ttl_seconds: int) -> str:
        return f"https://storage.test/get/{key}?ttl={ttl_seconds}"

    def object_size(self, key: str) -> int | None:
        data = self.objects.get(key)
        return None if data is None else len(data)

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)
        self.deleted.append(key)

    def upload(self, url: str, data: bytes) -> None:
        """What the client does with the presigned PUT URL."""
        self.objects[url.split("/put/", 1)[1].split("?", 1)[0]] = data


def make_app(
    settings: Settings | None = None,
    session_factory: sessionmaker[Session] | None = None,
    *,
    object_storage: Any = "fake",
) -> tuple[FastAPI, FakeAsyncRedis]:
    fake = FakeAsyncRedis()
    app = create_app(
        settings or make_settings(),
        redis=fake,
        session_factory=session_factory or make_session_factory(),
        object_storage=FakeObjectStorage() if object_storage == "fake" else object_storage,
    )
    return app, fake
