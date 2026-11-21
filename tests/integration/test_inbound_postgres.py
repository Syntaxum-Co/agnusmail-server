"""Inbound gateway on PostgreSQL + Redis: delivery and migration 0014 rules."""

import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.openpgp import generate_gateway_key, load_gateway_key
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.identity.models import User
from agnusmail.modules.inbound.delivery import Arrival, GatewayContext, deliver
from agnusmail.modules.messages.models import Message, MessageOrigin
from tests.integration.test_messages_postgres import live_person

pytestmark = pytest.mark.integration


@pytest.fixture
def settings_env() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def engine(settings_env: Settings) -> Iterator[Engine]:
    db_engine = create_db_engine(settings_env)
    try:
        yield db_engine
    finally:
        db_engine.dispose()


def test_external_delivery_on_postgres(settings_env: Settings, engine: Engine) -> None:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    alice = live_person(settings_env, factory)
    try:
        name = "in" + secrets.token_hex(6)
        assert alice.client.post("/v1/addresses", json={"local_part": name}).status_code == 201
        arrival = Arrival(
            content=b"Subject: hi\r\n\r\nTEST-ONLY\r\n",
            mail_from="someone@example.org",
            helo="mx.example.org",
            peer="192.0.2.1",
            hostname=settings_env.mail_domain,
            esmtp=True,
            received_at=datetime.now(UTC),
        )
        key = load_gateway_key(generate_gateway_key(), now=datetime.now(UTC))
        ctx = GatewayContext.from_settings(settings_env, key)
        with factory() as session, session.begin():
            [message] = deliver(
                session, [f"{name}@{settings_env.mail_domain}"], arrival, ctx, datetime.now(UTC)
            )
        inbox = alice.client.get("/v1/messages", params={"folder": "inbox"}).json()["items"]
        assert [(m["id"], m["origin"], m["sender"]) for m in inbox][:1] == [
            (str(message.id), "external", None)
        ]
    finally:
        alice.client.__exit__(None, None, None)


def test_postgres_ties_origin_to_sender(engine: Engine) -> None:
    factory = sessionmaker(bind=engine)
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        user_id = user.id
    for sender_id, origin in (
        (None, MessageOrigin.INTERNAL),  # internal needs a sender
        (user_id, MessageOrigin.EXTERNAL),  # external has none
        (user_id, "forwarded"),  # unknown origin
    ):
        with pytest.raises(IntegrityError), factory() as session, session.begin():
            session.add(
                Message(
                    sender_id=sender_id,
                    origin=origin,
                    client_message_id=uuid.uuid4().hex,
                    body=b"x",
                    size=1,
                )
            )
