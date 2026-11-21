"""Tests for agnusmail.core.config."""

from typing import Any

import pytest
from pydantic import ValidationError

from agnusmail.core.config import Environment, Settings
from tests.unit.fakes import make_settings

TLS_DSN = "postgresql+psycopg://user:pass@db:5432/agnusmail?sslmode=verify-full"
DEPLOYED: dict[str, Any] = {
    "database_url": TLS_DSN,
    "force_https": True,
    "siwe_domain": "mail.example.com",
    "siwe_uri": "https://mail.example.com/login",
    "mail_domain": "example.com",
    "recovery_decoy_secret": "test-only-decoy-secret-0123456789abcdef",
}


def test_settings_load_with_valid_environment() -> None:
    settings = make_settings()
    assert settings.environment is Environment.LOCAL  # the test helper opts in
    assert settings.redis_socket_timeout_seconds == 1.0
    assert settings.db_pool_size == 10


def test_settings_read_prefixed_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGNUSMAIL_DATABASE_URL", "postgresql+psycopg://u:p@h/db")
    monkeypatch.setenv("AGNUSMAIL_REDIS_URL", "redis://h:6379/0")
    monkeypatch.setenv("AGNUSMAIL_RATE_LIMIT_PER_IP", "7")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://wrong/db")
    monkeypatch.setenv("AGNUSMAIL_ENVIRONMENT", "local")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.database_url == "postgresql+psycopg://u:p@h/db"
    assert settings.rate_limit_per_ip == 7


def test_the_default_environment_is_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forgetting AGNUSMAIL_ENVIRONMENT must not turn the deployed checks off."""
    monkeypatch.delenv("AGNUSMAIL_ENVIRONMENT", raising=False)
    monkeypatch.setenv("AGNUSMAIL_DATABASE_URL", "postgresql+psycopg://u:p@h/db")
    monkeypatch.setenv("AGNUSMAIL_REDIS_URL", "redis://h:6379/0")
    with pytest.raises(ValidationError, match="production"):
        Settings(_env_file=None)  # type: ignore[call-arg]
    monkeypatch.setenv("AGNUSMAIL_ENVIRONMENT", "local")
    assert Settings(_env_file=None).environment is Environment.LOCAL  # type: ignore[call-arg]


def test_secret_urls_are_not_logged_in_repr() -> None:
    assert "user:pass" not in repr(make_settings())


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_deployed_environment_with_secure_values_ok(environment: str) -> None:
    settings = make_settings(environment=environment, **DEPLOYED)
    assert settings.environment.value == environment


@pytest.mark.parametrize("environment", ["staging", "production"])
@pytest.mark.parametrize(
    "override",
    [
        {"database_url": "postgresql+psycopg://user:pass@db/agnusmail"},
        {"database_url": "postgresql+psycopg://u:p@db/agnusmail?sslmode=disable"},
        {"database_url": "postgresql+psycopg://u:p@db/x?application_name=sslmode=require"},
        {"force_https": False},
        {"siwe_domain": "app.agnusmail"},
        {"siwe_domain": ""},
        {"siwe_uri": "https://app.agnusmail/login"},
        {"siwe_uri": "http://mail.example.com/login"},
        {"portal_base_url": "http://mail.example.com/portal"},
        {"recovery_decoy_secret": "too-short"},
    ],
)
def test_deployed_environment_rejects_insecure_values(
    environment: str, override: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        make_settings(environment=environment, **{**DEPLOYED, **override})


def test_cors_wildcard_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(cors_allowed_origins=["*"])


def test_samesite_none_requires_https() -> None:
    with pytest.raises(ValidationError):
        make_settings(session_cookie_samesite="none")
    assert make_settings(session_cookie_samesite="none", force_https=True)


def test_absolute_session_ttl_must_cover_idle_ttl() -> None:
    with pytest.raises(ValidationError):
        make_settings(session_cookie_max_age_seconds=600, session_absolute_ttl_seconds=60)
