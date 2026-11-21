"""Error mapping of the transactional helper used by every device/key endpoint."""

import secrets

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import (
    ConflictError,
    DatabaseUnavailableError,
    ResourceNotFoundError,
)
from agnusmail.infrastructure.database.transaction import run_in_transaction, run_sync_transaction
from agnusmail.modules.identity.models import User
from tests.unit.fakes import make_session_factory


def test_missing_factory_is_503() -> None:
    with pytest.raises(DatabaseUnavailableError):
        run_sync_transaction(None, lambda s: None)


def test_integrity_errors_become_conflict_and_roll_back() -> None:
    factory = make_session_factory()
    address = "0x" + secrets.token_hex(20)

    def insert_twice(session: Session) -> None:
        session.add(User(ethereum_address=address))
        session.flush()
        session.add(User(ethereum_address=address))
        session.flush()

    with pytest.raises(ConflictError):
        run_sync_transaction(factory, insert_twice)
    with factory() as session:
        assert session.query(User).filter_by(ethereum_address=address).count() == 0


def test_other_database_errors_become_503() -> None:
    def broken(session: Session) -> None:
        raise OperationalError("SELECT 1", {}, Exception("server closed the connection"))

    with pytest.raises(DatabaseUnavailableError) as caught:
        run_sync_transaction(make_session_factory(), broken)
    assert "server closed" not in caught.value.detail


async def test_domain_errors_propagate_and_roll_back() -> None:
    factory = make_session_factory()
    address = "0x" + secrets.token_hex(20)

    def add_then_fail(session: Session) -> None:
        session.add(User(ethereum_address=address))
        session.flush()
        raise ResourceNotFoundError("device not found")

    with pytest.raises(ResourceNotFoundError):
        await run_in_transaction(factory, add_then_fail)
    with factory() as session:
        assert session.query(User).filter_by(ethereum_address=address).count() == 0
