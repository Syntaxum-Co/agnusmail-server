"""Tests for user registration and the initial migration."""

import io
import uuid
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from eth_account import Account
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.infrastructure.database.base import Base
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.modules.identity.repository import (
    InvalidAddressError,
    get_by_address,
    get_by_id,
    normalize_address,
    register_login,
)
from tests.unit.fakes import make_app, make_session_factory
from tests.unit.test_auth import build_message, sign

CHECKSUM_ADDRESS = "0x" + "aB" * 20


def test_normalize_address() -> None:
    assert normalize_address(CHECKSUM_ADDRESS) == CHECKSUM_ADDRESS.lower()
    for bad in ("0x1234", "aB" * 21, "0x" + "zz" * 20, ""):
        with pytest.raises(InvalidAddressError):
            normalize_address(bad)


def test_register_login_creates_once_and_is_case_insensitive() -> None:
    factory = make_session_factory()
    now = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    with factory() as session, session.begin():
        first = register_login(session, CHECKSUM_ADDRESS, now)
        first_id = first.id
    with factory() as session, session.begin():
        again = register_login(session, CHECKSUM_ADDRESS.lower(), now)
        assert again.id == first_id
    with factory() as session:
        assert session.scalars(select(User)).all() == [get_by_id(session, first_id)]
        user = get_by_address(session, CHECKSUM_ADDRESS.upper().replace("0X", "0x"))
        assert user is not None
        assert user.ethereum_address == CHECKSUM_ADDRESS.lower()
        assert user.status == UserStatus.ACTIVE
        assert user.last_login_at is not None


def test_database_enforces_unique_and_lowercase_addresses() -> None:
    factory = make_session_factory()
    with factory() as session, session.begin():
        session.add(User(ethereum_address=CHECKSUM_ADDRESS.lower()))
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(User(ethereum_address=CHECKSUM_ADDRESS.lower()))
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(User(ethereum_address=CHECKSUM_ADDRESS))  # mixed case
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(User(ethereum_address="0x1234"))  # wrong length
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(User(ethereum_address="0x" + "1" * 40, status="deleted"))


def login(client: TestClient) -> tuple[str, str]:
    acct = Account.create()
    nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
    response = client.post(
        "/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct)
    )
    assert response.status_code == 200, response.text
    return response.json()["user_id"], acct.address


def test_login_registers_user_and_session_carries_user_id() -> None:
    factory = make_session_factory()
    app, _ = make_app(session_factory=factory)
    with TestClient(app, raise_server_exceptions=False) as client:
        user_id, address = login(client)
        session_data = client.get("/v1/auth/session").json()
    session_id = session_data.pop("session_id")
    assert session_data.pop("auth_method") == "siwe"
    assert session_data == {"user_id": user_id, "address": address}
    assert len(session_id) == 16 and int(session_id, 16) >= 0  # public id, not the token
    with factory() as session:
        user = get_by_id(session, uuid.UUID(user_id))
        assert user is not None
        assert user.ethereum_address == address.lower()


def test_suspended_user_cannot_log_in() -> None:
    factory = make_session_factory()
    acct = Account.create()
    with factory() as session, session.begin():
        session.add(User(ethereum_address=acct.address.lower(), status=UserStatus.SUSPENDED))
    app, _ = make_app(session_factory=factory)
    with TestClient(app, raise_server_exceptions=False) as client:
        nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
        response = client.post(
            "/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct)
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "ACCOUNT_SUSPENDED"
        assert client.get("/v1/auth/session").status_code == 401


def test_login_with_database_down_is_503_without_leaking_details() -> None:
    def broken_factory() -> Session:
        raise OperationalError("SELECT 1", {}, Exception("connection refused to db:5432"))

    app, _ = make_app(session_factory=broken_factory)  # type: ignore[arg-type]
    with TestClient(app, raise_server_exceptions=False) as client:
        acct = Account.create()
        nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
        response = client.post(
            "/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct)
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DatabaseUnavailableError"
    assert "5432" not in response.text


def test_migration_matches_models() -> None:
    """Offline (PostgreSQL) DDL of the migrations declares every table, column,
    constraint and index of the models (the CI/`alembic check` compares live schemas)."""
    buffer = io.StringIO()
    config = Config("alembic.ini", output_buffer=buffer)
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AGNUSMAIL_DATABASE_URL", "postgresql+psycopg://u:p@localhost/agnusmail")
        command.upgrade(config, "head", sql=True)
    ddl = buffer.getvalue()
    for table in Base.metadata.sorted_tables:
        assert f"CREATE TABLE {table.name} (" in ddl, table.name
        for column in table.columns:
            assert f"{column.name} " in ddl, f"{table.name}.{column.name}"
        for constraint in table.constraints:
            assert f"CONSTRAINT {constraint.name} " in ddl, constraint.name
        for index in table.indexes:
            assert f"INDEX {index.name} ON {table.name}" in ddl, index.name


def test_sqlite_schema_has_constraints() -> None:
    factory: sessionmaker[Session] = make_session_factory()
    with factory() as session:
        ddl = session.execute(
            text("SELECT sql FROM sqlite_master WHERE name = 'users'")
        ).scalar_one()
    assert "uq_users_ethereum_address" in ddl
    assert "ck_users_address_hex" not in ddl  # PostgreSQL-only regex check
