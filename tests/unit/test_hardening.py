"""Tests for timeouts, migration DSN escaping, log throttling, __Host- cookies, API prefix."""

from typing import Any

import pytest
from alembic.config import Config
from eth_account import Account
from fastapi.testclient import TestClient

from agnusmail.core.security import SECURE_SESSION_COOKIE_NAME
from agnusmail.infrastructure.database import session as db_session
from agnusmail.infrastructure.redis.client import RedisClient
from agnusmail.testing.auth import build_message, sign
from agnusmail.testing.fakes import make_app, make_settings


def test_redis_pool_has_socket_timeouts() -> None:
    settings = make_settings(redis_socket_timeout_seconds=0.5, redis_connect_timeout_seconds=0.25)
    pool = RedisClient(settings).create_pool()
    assert pool.connection_kwargs["socket_timeout"] == 0.5
    assert pool.connection_kwargs["socket_connect_timeout"] == 0.25
    assert pool.connection_kwargs["health_check_interval"] == 30


def test_db_engine_has_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_create_engine(url: str, **kwargs: Any) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(db_session, "create_engine", fake_create_engine)
    db_session.create_db_engine(make_settings(db_connect_timeout_seconds=3))
    assert captured["connect_args"]["connect_timeout"] == 3
    assert "statement_timeout=" in captured["connect_args"]["options"]


def test_alembic_accepts_url_encoded_passwords() -> None:
    url = "postgresql+psycopg://user:p%40ss%25@db/agnusmail"
    config = Config()
    config.set_main_option("sqlalchemy.url", db_session.alembic_config_value(url))
    assert config.get_main_option("sqlalchemy.url") == url


def test_rate_limit_backend_warning_is_throttled(capsys: pytest.CaptureFixture[str]) -> None:
    app, fake = make_app()
    fake.fail = True
    with TestClient(app, raise_server_exceptions=False) as client:
        capsys.readouterr()
        for _ in range(5):
            assert client.get("/nowhere").status_code == 404
    warnings = [
        line for line in capsys.readouterr().out.splitlines() if "rate_limit_backend" in line
    ]
    assert len(warnings) == 1


def test_secure_cookie_uses_host_prefix_end_to_end() -> None:
    app, _ = make_app(make_settings(force_https=True))
    with TestClient(app, base_url="https://testserver", raise_server_exceptions=False) as client:
        acct = Account.create()
        nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
        response = client.post(
            "/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct)
        )
        assert response.status_code == 200
        set_cookie = response.headers["set-cookie"]
        assert set_cookie.startswith(f"{SECURE_SESSION_COOKIE_NAME}=")
        assert "Secure" in set_cookie and "Path=/" in set_cookie and "Domain" not in set_cookie
        assert client.get("/v1/auth/session").json()["address"] == acct.address


def test_auth_routes_are_versioned_and_probes_are_not() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.post("/v1/auth/siwe/nonce").status_code == 200
        assert client.post("/auth/siwe/nonce").status_code == 404
        assert client.get("/healthz").status_code == 200
