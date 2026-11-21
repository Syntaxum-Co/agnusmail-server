"""Database role separation: units that need no PostgreSQL."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from agnusmail.infrastructure.database import roles
from agnusmail.infrastructure.database.base import Base
from agnusmail.infrastructure.database.roles import (
    ADMIN_ONLY_TABLES,
    OWNER_ONLY_TABLES,
    RUNTIME_TABLE_PRIVILEGES,
    RoleProvisioningError,
    check_runtime_role,
    provision_runtime_role,
    runtime_role_problems,
)
from agnusmail.testing.fakes import FakeAsyncRedis, make_settings


def test_every_table_has_an_explicit_runtime_privilege_decision() -> None:
    # Every table is either granted to the runtime role or explicitly admin-only.
    assert set(RUNTIME_TABLE_PRIVILEGES) | ADMIN_ONLY_TABLES == set(Base.metadata.tables)
    assert not OWNER_ONLY_TABLES & set(RUNTIME_TABLE_PRIVILEGES)
    assert not ADMIN_ONLY_TABLES & set(RUNTIME_TABLE_PRIVILEGES)


def test_least_privilege_on_the_audit_tables() -> None:
    assert "UPDATE" not in RUNTIME_TABLE_PRIVILEGES["audit_events"]
    assert "DELETE" not in RUNTIME_TABLE_PRIVILEGES["audit_chain_heads"]
    granted = {p for privileges in RUNTIME_TABLE_PRIVILEGES.values() for p in privileges}
    assert granted <= {"SELECT", "INSERT", "UPDATE", "DELETE"}  # never TRUNCATE/TRIGGER


@pytest.mark.parametrize("name", ["", "App", "1app", "app-role", 'x"; DROP ROLE y; --', "a" * 64])
def test_role_names_are_validated(name: str) -> None:
    engine = create_engine("sqlite://")
    with engine.connect() as connection, pytest.raises(RoleProvisioningError, match="name"):
        provision_runtime_role(connection, name, "secret")
    engine.dispose()


def test_non_postgresql_backends_have_no_roles() -> None:
    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        assert runtime_role_problems(connection) == []
        with pytest.raises(RoleProvisioningError, match="PostgreSQL"):
            provision_runtime_role(connection, "agnusmail_app", "secret")
    engine.dispose()


class _Unreachable:
    def connect(self) -> Any:
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))


def test_unreachable_database_skips_the_check() -> None:
    assert check_runtime_role(_Unreachable(), strict=True) == []  # type: ignore[arg-type]


def test_strict_mode_refuses_a_privileged_role(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(roles, "runtime_role_problems", lambda _c: ["superuser"])
    engine = create_engine("sqlite://")
    with pytest.raises(RoleProvisioningError, match="superuser"):
        check_runtime_role(engine, strict=True)
    assert check_runtime_role(engine, strict=False) == ["superuser"]  # local: warn only
    engine.dispose()


def test_api_startup_runs_the_role_check(monkeypatch: pytest.MonkeyPatch) -> None:
    from agnusmail.apps.api import main as api_main

    calls: list[bool] = []

    def refuse(_engine: Any, *, strict: bool) -> list[str]:
        calls.append(strict)
        raise RoleProvisioningError("refusing to start")

    monkeypatch.setattr(api_main, "check_runtime_role", refuse)
    app = api_main.create_app(make_settings(), redis=FakeAsyncRedis())
    with pytest.raises(RoleProvisioningError), TestClient(app):
        pass
    assert calls == [False]  # make_settings() is the local environment


def test_provisioning_cli_requires_its_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("AGNUSMAIL_DB_APP_PASSWORD", raising=False)
    monkeypatch.setenv("AGNUSMAIL_DATABASE_URL", "postgresql+psycopg://u:p@localhost/x")
    assert roles.main() == 2
    assert "AGNUSMAIL_DB_APP_PASSWORD" in capsys.readouterr().err
