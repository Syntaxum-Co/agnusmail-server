"""Messages end to end on PostgreSQL + Redis."""

import secrets
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.identity.models import User
from agnusmail.modules.messages.models import Message
from agnusmail.testing.auth import login
from agnusmail.testing.devices import onboard
from agnusmail.testing.people import PLAINTEXT, Person, bind_session, compose
from tests.client_decrypt import open_message

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


def live_person(settings: Settings, factory: sessionmaker[Session]) -> Person:
    """A user with its own app instance: the async Redis pool is bound to the event loop
    of one TestClient, so clients cannot share an app against a real Redis. The database
    engine is shared and owned by the test (the app's own engine is process-global)."""
    from agnusmail.apps.api.main import create_app

    app = create_app(settings, session_factory=factory)
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()  # run the lifespan
    user = login(client)
    device = onboard(client, user)
    bind_session(client, device)
    return Person(client, user, device)


def test_message_round_trip_on_postgres(settings_env: Settings, engine: Engine) -> None:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    alice, bob = live_person(settings_env, factory), live_person(settings_env, factory)
    try:
        payload = compose(alice, [bob])
        sent = alice.client.post("/v1/messages", json=payload)
        assert sent.status_code == 201, sent.text
        assert open_message(bob, sent.json()["id"], alice) == PLAINTEXT
        assert alice.client.post("/v1/messages", json=payload).status_code == 409  # replay
    finally:
        alice.client.__exit__(None, None, None)
        bob.client.__exit__(None, None, None)


def test_postgres_enforces_message_constraints(engine: Engine) -> None:
    factory = sessionmaker(bind=engine)
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        user_id = user.id
    for values in (
        {"client_message_id": "Z" * 32, "body": b"x", "size": 1},  # not lowercase hex
        {"client_message_id": "a" * 32, "body": b"xy", "size": 1},  # size mismatch
    ):
        with pytest.raises(IntegrityError), factory() as session, session.begin():
            session.add(Message(sender_id=user_id, **values))
