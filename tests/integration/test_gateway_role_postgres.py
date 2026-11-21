"""The inbound gateway's own PostgreSQL role.

Provisioned by the owner, then every check runs over a connection AS the gateway role:
it delivers a real external message and is refused everything else.
"""

import secrets
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.roles import (
    GATEWAY_TABLE_PRIVILEGES,
    RoleProvisioningError,
    check_runtime_role,
    excess_privileges,
    provision_gateway_role,
)
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.openpgp import generate_gateway_key, load_gateway_key
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.inbound.delivery import (
    Arrival,
    GatewayContext,
    deliver,
    register_gateway_key,
)
from tests.integration.test_messages_postgres import live_person

pytestmark = pytest.mark.integration

ROLE = "agnusmail_gateway_it"


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


@pytest.fixture(scope="module")
def gateway(owner: Engine) -> Iterator[Engine]:
    password = secrets.token_urlsafe(24)
    with owner.begin() as connection:
        provision_gateway_role(connection, ROLE, password)
    engine = create_engine(make_url(owner.url).set(username=ROLE, password=password))
    try:
        yield engine
    finally:
        engine.dispose()


def test_gateway_role_holds_exactly_its_map(owner: Engine, gateway: Engine) -> None:
    assert check_runtime_role(gateway, strict=True, allowed=GATEWAY_TABLE_PRIVILEGES) == []
    with owner.connect() as connection:
        assert excess_privileges(connection, GATEWAY_TABLE_PRIVILEGES)  # the owner has more
    with pytest.raises(RoleProvisioningError):
        check_runtime_role(owner, strict=True, allowed=GATEWAY_TABLE_PRIVILEGES)


def test_gateway_role_delivers_and_nothing_else(
    settings_env: Settings, owner: Engine, gateway: Engine
) -> None:
    alice = live_person(settings_env, sessionmaker(bind=owner, expire_on_commit=False))
    try:
        name = "gw" + secrets.token_hex(6)
        assert alice.client.post("/v1/addresses", json={"local_part": name}).status_code == 201
        key = load_gateway_key(generate_gateway_key(), now=datetime.now(UTC))
        factory = sessionmaker(bind=gateway, expire_on_commit=False)
        arrival = Arrival(
            content=b"Subject: hi\r\n\r\nTEST-ONLY\r\n",
            mail_from="someone@example.org",
            helo="mx.example.org",
            peer="192.0.2.1",
            hostname=settings_env.mail_domain,
            esmtp=True,
            received_at=datetime.now(UTC),
        )
        with factory() as session, session.begin():  # as the gateway process does
            register_gateway_key(session, key)
            ctx = GatewayContext.from_settings(settings_env, key)
            address = f"{name}@{settings_env.mail_domain}"
            [message] = deliver(session, [address], arrival, ctx, datetime.now(UTC))
        inbox = alice.client.get("/v1/messages", params={"folder": "inbox"}).json()["items"]
        assert inbox[0]["id"] == str(message.id)
    finally:
        alice.client.__exit__(None, None, None)

    forbidden = [
        "SELECT body FROM messages LIMIT 1",  # cannot read any ciphertext back
        "SELECT * FROM audit_events LIMIT 1",
        "SELECT * FROM mailbox_entries LIMIT 1",
        "SELECT * FROM jobs LIMIT 1",
        "UPDATE users SET status = status",
        "DELETE FROM gateway_keys",
        "UPDATE mail_addresses SET status = status",
    ]
    for statement in forbidden:
        with pytest.raises(DBAPIError, match="permission denied"), gateway.begin() as connection:
            connection.execute(text(statement))
