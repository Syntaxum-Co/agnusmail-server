"""Custom domains on PostgreSQL: what the database itself enforces,
and resolution by the inbound gateway's own role."""

import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.roles import provision_gateway_role
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.addresses.models import MailAddress
from agnusmail.modules.addresses.service import resolve
from agnusmail.modules.domains.models import MailDomain
from agnusmail.modules.identity.models import User

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def settings_env() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture(scope="module")
def owner(settings_env: Settings) -> Iterator[Engine]:
    engine = create_db_engine(settings_env)
    try:
        yield engine
    finally:
        engine.dispose()


def new_user(engine: Engine) -> uuid.UUID:
    with Session(engine) as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        return user.id


def add_address(engine: Engine, user_id: uuid.UUID, domain: str, kind: str) -> uuid.UUID:
    local = "a" + secrets.token_hex(4)
    with Session(engine) as session, session.begin():
        row = MailAddress(
            user_id=user_id,
            local_part=local,
            canonical=local.replace("1", "l").replace("0", "o"),
            domain=domain,
            status="active",
            kind=kind,
        )
        session.add(row)
        session.flush()
        return row.id


def verified_domain(engine: Engine, user_id: uuid.UUID, name: str) -> None:
    with Session(engine) as session, session.begin():
        session.add(
            MailDomain(
                user_id=user_id,
                name=name,
                status="verified",
                token=secrets.token_hex(16),
                verified_at=datetime.now(UTC),
            )
        )


def test_only_domain_addresses_can_be_deleted(owner: Engine, settings_env: Settings) -> None:
    user = new_user(owner)
    primary = add_address(owner, user, f"p{secrets.token_hex(4)}.example.com", "primary")
    custom = add_address(owner, user, f"c{secrets.token_hex(4)}.example.com", "domain")
    with owner.connect() as connection, pytest.raises(DBAPIError, match="never deleted"):
        connection.execute(text("DELETE FROM mail_addresses WHERE id = :i"), {"i": primary})
    with owner.begin() as connection:
        deleted = connection.execute(
            text("DELETE FROM mail_addresses WHERE id = :i"), {"i": custom}
        )
        assert deleted.rowcount == 1


def test_one_verified_holder_per_domain(owner: Engine) -> None:
    name = f"v{secrets.token_hex(4)}.example.com"
    verified_domain(owner, new_user(owner), name)
    with pytest.raises(IntegrityError):
        verified_domain(owner, new_user(owner), name)


def test_gateway_role_resolves_custom_domain_addresses(
    owner: Engine, settings_env: Settings
) -> None:
    role, password = "agnusmail_gateway_dom_it", secrets.token_urlsafe(24)
    with owner.begin() as connection:
        provision_gateway_role(connection, role, password)
    gateway = create_engine(make_url(owner.url).set(username=role, password=password))
    try:
        user = new_user(owner)
        name = f"g{secrets.token_hex(4)}.example.com"
        verified_domain(owner, user, name)
        address_id = add_address(owner, user, name, "domain")
        with Session(owner) as session:
            row = session.get(MailAddress, address_id)
            assert row is not None
            email = row.email
        with sessionmaker(bind=gateway)() as session:
            _, found = resolve(session, email, settings_env.mail_domain)
            assert found.id == user
    finally:
        gateway.dispose()
