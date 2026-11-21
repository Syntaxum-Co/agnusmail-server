"""Outbound delivery on PostgreSQL (protocol v1 §10).

Real database and Redis, the API for submission, the outbound service's own database
role for delivery and a local SMTP server as the recipient's MTA. Checked: DKIM as a
receiver verifies it, the queue keeps no plaintext and no ciphertext after delivery,
concurrent service instances never send a message twice, the role can do its job and
nothing else, and the database itself enforces the 72 h limit.
"""

import base64
import secrets
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import dkim
import pysequoia
import pytest
from agnusmail.apps.smtp_outbound.__main__ import register_queue_key
from sqlalchemy import Engine, create_engine, make_url, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.roles import (
    OUTBOUND_TABLE_PRIVILEGES,
    check_runtime_role,
    provision_outbound_role,
)
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.outbound.delivery import SmtpDelivery
from agnusmail.modules.outbound.dkim import DkimSigner, generate_dkim_key
from agnusmail.modules.outbound.models import (
    OutboundMessage,
    OutboundRecipient,
    OutboundStatus,
)
from agnusmail.modules.outbound.queue_key import QueueKey, generate_queue_key, load_queue_key
from agnusmail.modules.outbound.sender import OutboundSender
from tests.integration.test_inbound_no_plaintext import found_in_database, found_in_redis
from tests.integration.test_messages_postgres import live_person
from tests.outbound_helpers import FakeResolver, TestMta
from tests.unit.test_messages import Person
from tests.unit.test_outbound_dkim import receiver_dns

pytestmark = pytest.mark.integration

ROLE = "agnusmail_outbound_it"


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
def outbound(owner: Engine) -> Iterator[Engine]:
    password = secrets.token_urlsafe(24)
    with owner.begin() as connection:
        provision_outbound_role(connection, ROLE, password)
    engine = create_engine(make_url(owner.url).set(username=ROLE, password=password))
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def queue_key(outbound: Engine) -> QueueKey:
    key = load_queue_key(generate_queue_key(), now=datetime.now(UTC))
    with sessionmaker(bind=outbound)() as session, session.begin():
        register_queue_key(session, key)  # as the outbound role, like the service
    return key


@pytest.fixture(scope="module")
def signer(settings_env: Settings) -> DkimSigner:
    return DkimSigner(settings_env.mail_domain, "agnus1", generate_dkim_key())


@pytest.fixture
def mta() -> Iterator[TestMta]:
    server = TestMta()
    server.start()
    yield server
    server.stop()


@pytest.fixture(autouse=True)
def settle_leftovers(owner: Engine) -> None:
    """Queued rows left by earlier runs would compete for the batch: settle them."""
    with owner.begin() as connection:
        connection.execute(
            update(OutboundMessage)
            .where(OutboundMessage.status == OutboundStatus.QUEUED)
            .values(status=OutboundStatus.EXPIRED, payload=None, finished_at=datetime.now(UTC))
        )


@pytest.fixture
def alice(settings_env: Settings, owner: Engine) -> Iterator[tuple[Person, str]]:
    person = live_person(settings_env, sessionmaker(bind=owner, expire_on_commit=False))
    name = "ob" + secrets.token_hex(6)
    assert person.client.post("/v1/addresses", json={"local_part": name}).status_code == 201
    yield person, f"{name}@{settings_env.mail_domain}"
    person.client.__exit__(None, None, None)


def submit(person: Person, key: QueueKey, plaintext: bytes, recipients: list[str]) -> str:
    cert = pysequoia.Cert.from_bytes(key.certificate)
    payload = pysequoia.encrypt(plaintext, recipients=[cert], armor=False)
    response = person.client.post(
        "/v1/outbound/messages",
        json={
            "version": 1,
            "message_id": secrets.token_hex(16),
            "recipients": recipients,
            "payload": base64.b64encode(payload).decode(),
        },
    )
    assert response.status_code == 202, response.text
    return str(response.json()["id"])


def sender_for(
    engine: Engine, key: QueueKey, signer: DkimSigner, mta: TestMta, settings: Settings
) -> OutboundSender:
    return OutboundSender(
        sessionmaker(bind=engine, expire_on_commit=False),
        keys=[key],
        signer=signer,
        transport=SmtpDelivery(
            hostname="out.example.com", resolver=FakeResolver(), relay=mta.relay
        ),
        mail_domain=settings.mail_domain,
        batch_size=5,
    )


def test_delivery_as_the_outbound_role_leaves_nothing_behind(
    settings_env: Settings,
    owner: Engine,
    outbound: Engine,
    queue_key: QueueKey,
    signer: DkimSigner,
    mta: TestMta,
    alice: tuple[Person, str],
) -> None:
    person, address = alice
    marker = "testonly" + secrets.token_hex(12)
    plaintext = (
        f"From: {address}\r\nTo: friend@example.org\r\nSubject: {marker}\r\n\r\n{marker} body\r\n"
    ).encode()
    outbound_id = submit(person, queue_key, plaintext, ["friend@example.org"])
    # While queued: ciphertext only.
    assert found_in_database(owner, marker) == []

    sender_for(outbound, queue_key, signer, mta, settings_env).run_once(datetime.now(UTC))

    [received] = mta.recorder.received
    assert marker.encode() in received.content
    dns = receiver_dns(signer.private_key, domain=settings_env.mail_domain)
    assert dkim.verify(received.content, dnsfunc=dns)
    with sessionmaker(bind=owner)() as session:
        row = session.get(OutboundMessage, uuid.UUID(outbound_id))
        assert row is not None and (row.status, row.payload) == ("done", None)
    assert found_in_database(owner, marker) == []
    assert found_in_redis(settings_env.redis_url, marker) == []


def test_concurrent_instances_send_each_message_once(
    settings_env: Settings,
    outbound: Engine,
    queue_key: QueueKey,
    signer: DkimSigner,
    mta: TestMta,
    alice: tuple[Person, str],
) -> None:
    person, address = alice
    tag = secrets.token_hex(4)
    ids = [
        submit(
            person,
            queue_key,
            f"From: {address}\r\nTo: x@example.org\r\nSubject: {tag} {n}\r\n\r\nx\r\n".encode(),
            [f"r{n}@example.org"],
        )
        for n in range(12)
    ]
    senders = [sender_for(outbound, queue_key, signer, mta, settings_env) for _ in range(4)]
    now = datetime.now(UTC)
    barrier = threading.Barrier(len(senders))

    def run(sender: OutboundSender) -> None:
        barrier.wait()
        for _ in range(6):
            sender.run_once(now)

    threads = [threading.Thread(target=run, args=(s,)) for s in senders]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    subjects = [
        line
        for r in mta.recorder.received
        for line in r.content.split(b"\r\n")
        if line.startswith(f"Subject: {tag} ".encode())
    ]
    with sessionmaker(bind=outbound)() as session:
        states = session.execute(
            select(OutboundMessage.status, OutboundRecipient.smtp_status)
            .join(OutboundRecipient, OutboundRecipient.outbound_message_id == OutboundMessage.id)
            .where(OutboundMessage.id.in_([uuid.UUID(i) for i in ids]))
        ).all()
    assert sorted(subjects) == sorted(f"Subject: {tag} {n}".encode() for n in range(12)), states
    assert {status for status, _ in states} == {"done"}


def test_outbound_role_holds_exactly_its_map(outbound: Engine) -> None:
    assert check_runtime_role(outbound, strict=True, allowed=OUTBOUND_TABLE_PRIVILEGES) == []
    for statement in (
        "SELECT count(*) FROM users",
        "SELECT count(*) FROM messages",
        "SELECT count(*) FROM public_keys",
        "SELECT count(*) FROM audit_events",
        "DELETE FROM outbound_messages",
        "INSERT INTO messages (id) VALUES (gen_random_uuid())",
    ):
        with outbound.connect() as connection, pytest.raises(DBAPIError):
            connection.execute(text(statement))


def test_database_enforces_the_queue_rules(owner: Engine, alice: tuple[Person, str]) -> None:
    person, _ = alice
    user_id = uuid.UUID(person.user.user_id)
    now = datetime.now(UTC)
    base = {
        "user_id": user_id,
        "kind": "message",
        "sender_address": "a@b.example",
        "key_fingerprint": "ab" * 32,
        "size": 3,
        "attempts": 0,
        "next_attempt_at": now,
        "created_at": now,
    }
    bad_rows: list[dict[str, Any]] = [
        {"status": "queued", "payload": b"abc", "expires_at": now + timedelta(hours=73)},
        {"status": "done", "payload": b"abc", "expires_at": now, "finished_at": now},
        {"status": "queued", "payload": None, "expires_at": now},
        {"status": "queued", "payload": b"abcd", "expires_at": now},
    ]
    for extra in bad_rows:
        with Session(owner) as session, pytest.raises(IntegrityError):
            session.add(OutboundMessage(client_message_id=secrets.token_hex(16), **base, **extra))
            session.commit()
