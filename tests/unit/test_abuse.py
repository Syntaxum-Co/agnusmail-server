"""Abuse and reputation from metadata only."""

import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.abuse.models import AbuseReport, AccountRestriction
from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.outbound.models import (
    OutboundMessage,
    OutboundRecipient,
    OutboundStatus,
)
from tests.unit.auth_helpers import login
from tests.unit.fakes import make_app, make_session_factory, make_settings
from tests.unit.test_messages import MESSAGES, Person, compose, person, send


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


def app_with(factory: sessionmaker[Session], **settings: Any) -> Any:
    return make_app(make_settings(**settings), factory)[0]


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return app_with(factory, abuse_report_threshold=2, abuse_restricted_messages_per_day=1)


@pytest.fixture
def people(app: Any) -> Iterator[list[Person]]:
    group = [person(app) for _ in range(3)]
    yield group
    for p in group:
        p.client.close()


def report(who: Person, message_id: str, category: str = "spam") -> Any:
    return who.client.post(f"{MESSAGES}/{message_id}/report", json={"category": category})


def test_report_is_metadata_only(people: list[Person], factory: sessionmaker[Session]) -> None:
    alice, bob, _ = people
    message_id = send(alice, compose(alice, [bob])).json()["id"]
    with_content = bob.client.post(
        f"{MESSAGES}/{message_id}/report", json={"category": "spam", "content": "TEST-ONLY"}
    )
    assert with_content.status_code == 422  # no field for content exists
    created = report(bob, message_id, "phishing")
    assert created.status_code == 201
    assert set(created.json()) == {"id", "category", "created_at"}
    with factory() as session:
        row = session.scalars(select(AbuseReport)).one()
        assert (str(row.reporter_id), str(row.reported_id), row.category) == (
            bob.user.user_id,
            alice.user.user_id,
            "phishing",
        )
        audit = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "abuse.reported")
        ).one()
        assert str(audit.user_id) == bob.user.user_id  # the reporter's own trail


def test_report_rules(app: Any, people: list[Person]) -> None:
    alice, bob, carol = people
    message_id = send(alice, compose(alice, [bob])).json()["id"]
    assert report(bob, message_id).status_code == 201
    assert report(bob, message_id).status_code == 409  # once per message
    assert report(alice, message_id).status_code == 409  # own message
    assert report(carol, message_id).status_code == 404  # does not hold it
    assert report(bob, str(uuid.uuid4())).status_code == 404
    assert (
        bob.client.post(f"{MESSAGES}/{message_id}/report", json={"category": "bad"}).status_code
        == 422
    )


def test_distinct_reporters_restrict_the_sender(
    people: list[Person], factory: sessionmaker[Session]
) -> None:
    alice, bob, carol = people
    first = send(alice, compose(alice, [bob, carol])).json()["id"]
    second = send(alice, compose(alice, [bob])).json()["id"]
    report(bob, first)
    report(bob, second)  # the same reporter twice counts once
    assert alice.client.get("/v1/abuse/status").json()["restricted"] is False
    report(carol, first)
    status = alice.client.get("/v1/abuse/status").json()
    assert (status["restricted"], status["reason"]) == (True, "reports")
    until = datetime.fromisoformat(status["restricted_until"])
    assert timedelta(days=6) < until - datetime.now(UTC) <= timedelta(days=7)
    with factory() as session:
        event = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "abuse.restricted")
        ).one()
        assert str(event.user_id) == alice.user.user_id and event.actor_user_id is None
        assert "reporter" not in str(event.details)
    # Restricted: a small daily allowance for internal mail.
    assert send(alice, compose(alice, [bob])).status_code == 201
    assert send(alice, compose(alice, [bob])).status_code == 429
    # Reading still works.
    assert alice.client.get(MESSAGES, params={"folder": "sent"}).status_code == 200


def test_restriction_blocks_outbound_and_portal_then_expires(
    app: Any, people: list[Person], factory: sessionmaker[Session]
) -> None:
    from tests.unit.test_outbound import claim, mime, register_outbound_key, submission

    alice = people[0]
    queue = register_outbound_key(factory)
    sender = claim(alice)
    owner = uuid.UUID(alice.user.user_id)
    with factory() as session, session.begin():
        session.add(
            AccountRestriction(
                user_id=owner,
                reason="reports",
                restricted_until=datetime.now(UTC) + timedelta(days=1),
            )
        )
    blocked = alice.client.post("/v1/outbound/messages", json=submission(queue, mime(sender)))
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "ACCOUNT_RESTRICTED"
    with factory() as session, session.begin():
        row = session.get(AccountRestriction, owner)
        assert row is not None
        row.restricted_until = datetime.now(UTC) - timedelta(seconds=1)
    assert alice.client.get("/v1/abuse/status").json()["restricted"] is False
    again = alice.client.post("/v1/outbound/messages", json=submission(queue, mime(sender)))
    assert again.status_code == 202


def test_bounce_rate_restricts_through_the_job(
    app: Any, people: list[Person], factory: sessionmaker[Session]
) -> None:
    from agnusmail.modules.jobs.handlers import evaluate_abuse
    from agnusmail.modules.jobs.queue import JobContext

    alice = people[0]
    owner = uuid.UUID(alice.user.user_id)
    now = datetime.now(UTC)
    with factory() as session, session.begin():
        message = OutboundMessage(
            user_id=owner,
            client_message_id=secrets.token_hex(16),
            kind="message",
            sender_address="a@b.example",
            key_fingerprint="ab" * 32,
            payload=None,
            size=1,
            status=OutboundStatus.DONE,
            attempts=1,
            next_attempt_at=now,
            expires_at=now + timedelta(hours=1),
            created_at=now,
            finished_at=now,
        )
        session.add(message)
        session.flush()
        for n in range(20):
            bounced = n < 7  # 35%
            session.add(
                OutboundRecipient(
                    outbound_message_id=message.id,
                    address=f"r{n}@example.org",
                    status="failed" if bounced else "delivered",
                    smtp_code=550 if bounced else 250,
                    updated_at=now,
                )
            )
    evaluate_abuse(JobContext(factory=factory, settings=app.state.settings), {})
    status = alice.client.get("/v1/abuse/status").json()
    assert (status["restricted"], status["reason"]) == (True, "bounces")


def test_internal_message_limit(factory: sessionmaker[Session]) -> None:
    app = app_with(factory, internal_messages_per_hour=2)
    alice, bob = person(app), person(app)
    codes = [send(alice, compose(alice, [bob])).status_code for _ in range(3)]
    assert codes == [201, 201, 429]


def test_outbound_per_domain_limit(factory: sessionmaker[Session]) -> None:
    from tests.unit.test_outbound import claim, mime, register_outbound_key, submission

    app = app_with(factory, outbound_per_domain_per_hour=2)
    queue = register_outbound_key(factory)
    alice = person(app)
    sender = claim(alice)
    many = ["a@example.org", "b@example.org", "c@example.org"]
    response = alice.client.post(
        "/v1/outbound/messages", json=submission(queue, mime(sender), many)
    )
    assert response.status_code == 429
    other = ["a@example.org", "b@example.net"]
    response = alice.client.post(
        "/v1/outbound/messages", json=submission(queue, mime(sender), other)
    )
    assert response.status_code == 202


def test_device_registrations_per_day(factory: sessionmaker[Session]) -> None:
    app = app_with(factory, device_registrations_per_day=2)
    alice = person(app)  # one registration already
    assert alice.client.post("/v1/devices", json={"name": "two"}).status_code == 201
    assert alice.client.post("/v1/devices", json={"name": "three"}).status_code == 429


def test_new_accounts_per_ip_per_day(factory: sessionmaker[Session]) -> None:
    from eth_account import Account

    from tests.unit.test_auth import build_message, sign

    app = app_with(factory, new_accounts_per_ip_per_day=2, rate_limit_auth_per_ip=100)
    with TestClient(app, raise_server_exceptions=False) as client:
        first = login(client)
        login(client)
        account = Account.create()
        nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
        refused = client.post(
            "/v1/auth/siwe/verify", json=sign(build_message(account.address, nonce), account)
        )
        assert refused.status_code == 429
        # Existing accounts still log in from the same IP.
        login(client, first.account)


def test_abuse_module_never_touches_content() -> None:
    """No abuse control needs message content."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "src/agnusmail/modules/abuse"
    for path in root.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for forbidden in (".body", ".payload", ".envelope", "decrypt", "session.get(Message"):
            assert forbidden not in text, (path.name, forbidden)
