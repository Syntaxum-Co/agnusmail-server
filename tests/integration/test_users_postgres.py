"""PostgreSQL integration tests for users (requires `alembic upgrade head` first, as in CI)."""

import secrets
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.base import Base
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules.identity.models import User
from agnusmail.modules.identity.repository import register_login

pytestmark = pytest.mark.integration


@pytest.fixture
def engine() -> Iterator[Engine]:
    db_engine = create_db_engine(Settings(_env_file=None))  # type: ignore[call-arg]
    try:
        yield db_engine
    finally:
        db_engine.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def random_address() -> str:
    return "0x" + secrets.token_hex(20)


def test_migrations_match_models(engine: Engine) -> None:
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, Base.metadata) == []


def test_postgres_constraints(factory: sessionmaker[Session]) -> None:
    address = random_address()
    with factory() as session, session.begin():
        session.add(User(ethereum_address=address))
    bad_values = [
        address,  # duplicate
        address.upper().replace("0X", "0x"),  # not lowercase
        "0x" + "g" * 40,  # not hex (PostgreSQL-only regex check)
    ]
    for value in bad_values:
        with pytest.raises(IntegrityError), factory() as session, session.begin():
            session.add(User(ethereum_address=value))
    with factory() as session, session.begin():
        session.execute(delete(User).where(User.ethereum_address == address))


def test_concurrent_first_logins_create_one_user(factory: sessionmaker[Session]) -> None:
    address = random_address()

    def login() -> str:
        with factory() as session, session.begin():
            return str(register_login(session, address, datetime.now(UTC)).id)

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = set(pool.map(lambda _: login(), range(16)))
    assert len(ids) == 1
    with factory() as session, session.begin():
        count = session.scalar(
            select(func.count()).select_from(User).where(User.ethereum_address == address)
        )
        assert count == 1
        session.execute(delete(User).where(User.ethereum_address == address))
