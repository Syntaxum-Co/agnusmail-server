"""Storage limit and account suspension: what grows is refused, reading never is."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.exceptions import AccountSuspendedError
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.modules.quotas.policy import (
    QuotaExceededError,
    QuotaPolicy,
    RecipientMailboxUnavailableError,
)
from agnusmail.modules.quotas.usage import add_usage
from tests.unit.fakes import make_app, make_session_factory, make_settings
from tests.unit.test_messages import MESSAGES, Person, compose, person, send

QUOTA = 1024**2  # the smallest limit the settings accept


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return make_app(make_settings(storage_quota_bytes=QUOTA), session_factory=factory)[0]


@pytest.fixture
def pair(app: Any) -> Iterator[tuple[Person, Person]]:
    alice, bob = person(app), person(app)
    yield alice, bob
    alice.client.close()
    bob.client.close()


def owner(who: Person) -> uuid.UUID:
    return uuid.UUID(who.user.user_id)


def fill(factory: sessionmaker[Session], who: Person, size: int) -> None:
    with factory() as session, session.begin():
        add_usage(session, owner(who), size)


def set_status(factory: sessionmaker[Session], who: Person, status: UserStatus) -> None:
    with factory() as session, session.begin():
        user = session.get(User, owner(who))
        assert user is not None
        user.status = status


def test_usage_reports_the_configured_limit(pair: tuple[Person, Person]) -> None:
    alice, _ = pair
    body = alice.client.get("/v1/usage").json()
    assert body == {"stored_bytes": 0, "quota_bytes": QUOTA, "full": False}


def test_sending_over_the_limit_is_refused(
    pair: tuple[Person, Person], factory: sessionmaker[Session]
) -> None:
    alice, bob = pair
    fill(factory, alice, QUOTA)
    response = send(alice, compose(alice, [bob]))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "QUOTA_EXCEEDED"
    assert alice.client.get("/v1/usage").json()["full"] is True
    assert alice.client.get(MESSAGES).status_code == 200  # reading still works


def test_a_full_recipient_cannot_receive(
    pair: tuple[Person, Person], factory: sessionmaker[Session]
) -> None:
    alice, bob = pair
    fill(factory, bob, QUOTA)
    response = send(alice, compose(alice, [bob]))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "RECIPIENT_MAILBOX_UNAVAILABLE"


def test_suspending_an_account_ends_its_sessions(
    pair: tuple[Person, Person], factory: sessionmaker[Session]
) -> None:
    alice, _ = pair
    set_status(factory, alice, UserStatus.SUSPENDED)
    response = alice.client.get("/v1/usage")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ACCOUNT_SUSPENDED"
    assert alice.client.get("/v1/usage").status_code == 401  # the session is gone
    set_status(factory, alice, UserStatus.ACTIVE)
    assert alice.client.get("/v1/usage").status_code == 401  # reinstating needs a login


def test_a_suspended_account_cannot_receive(
    pair: tuple[Person, Person], factory: sessionmaker[Session]
) -> None:
    alice, bob = pair
    payload = compose(alice, [bob])
    set_status(factory, bob, UserStatus.SUSPENDED)
    refused = send(alice, payload)
    assert refused.status_code == 422  # a suspended account is an unknown recipient
    assert refused.json()["error"]["code"] == "RECIPIENT_INVALID"


def test_policy_directly(factory: sessionmaker[Session]) -> None:
    policy = QuotaPolicy(quota_bytes=100)
    now = datetime.now(UTC)
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + "ab" * 20)
        session.add(user)
        session.flush()
        policy.require_space(session, user.id, 100, now)
        assert policy.accepts(session, user.id, 100, now)
        with pytest.raises(QuotaExceededError):
            policy.require_space(session, user.id, 101, now)
        add_usage(session, user.id, 100)
        assert not policy.accepts(session, user.id, 0, now)  # full takes nothing
        with pytest.raises(RecipientMailboxUnavailableError):
            policy.require_recipient(session, user.id, 0, now)
        user.status = UserStatus.SUSPENDED
        session.flush()
        with pytest.raises(AccountSuspendedError):
            policy.require_active(session, user.id, now)
