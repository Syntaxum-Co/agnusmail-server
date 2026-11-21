"""Tests for liveness and readiness endpoints."""

import asyncio
import time

from fastapi.testclient import TestClient

from agnusmail.apps.api.main import create_app
from agnusmail.infrastructure.database import session as db_session
from agnusmail.testing.fakes import FakeAsyncRedis, make_app, make_settings


def test_healthz_is_always_up() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_lifespan_initializes_and_disposes_database_engine() -> None:
    app = create_app(make_settings(), redis=FakeAsyncRedis())  # no injected DB: app owns it
    with TestClient(app):
        assert db_session.get_engine() is not None
        assert app.state.db_session_factory is not None
    assert db_session._engine is None  # noqa: SLF001


def test_readyz_default_db_check_uses_session_factory() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/readyz").status_code == 200  # SQLite SELECT 1 + fake PING


def test_readyz_returns_503_when_checks_fail() -> None:
    app, _ = make_app()

    def failing() -> bool:
        raise ConnectionError("no database in unit tests")

    with TestClient(app, raise_server_exceptions=False) as client:
        app.state.db_check = failing
        app.state.redis_check = failing
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "not_ready"
    assert "no database" not in response.text


def test_readyz_uses_injected_redis_and_reports_its_failure() -> None:
    app, fake = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        app.state.db_check = lambda: True
        assert client.get("/readyz").status_code == 200  # default redis check: fake PING
        fake.fail = True
        assert client.get("/readyz").status_code == 503


def test_readyz_times_out_slow_checks() -> None:
    app, _ = make_app(make_settings(readiness_timeout_seconds=0.1))

    def slow_db() -> bool:
        time.sleep(0.5)
        return True

    async def slow_redis() -> bool:
        await asyncio.sleep(0.5)
        return True

    with TestClient(app, raise_server_exceptions=False) as client:
        app.state.db_check = slow_db
        app.state.redis_check = slow_redis
        assert client.get("/readyz").status_code == 503


def test_readyz_returns_200_when_checks_pass() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        app.state.db_check = lambda: True
        app.state.redis_check = lambda: True
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
