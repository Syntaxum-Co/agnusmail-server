"""The outbound queue worker (protocol v1 §10).

From the user's submission through the API to the recipient's server: the queue is
opened only by the outbound service, signed with DKIM, delivered per recipient, retried
on temporary failures, and the ciphertext is erased when done or at 72 h.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import dkim
import pytest
from agnusmail.apps.smtp_outbound.__main__ import register_queue_key
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.outbound.delivery import Outcome, Result, SmtpDelivery
from agnusmail.modules.outbound.dkim import DkimSigner, generate_dkim_key
from agnusmail.modules.outbound.models import (
    QUEUE_LIMIT,
    OutboundMessage,
    OutboundRecipient,
)
from agnusmail.modules.outbound.queue_key import QueueKey, generate_queue_key, load_queue_key
from agnusmail.modules.outbound.sender import OutboundSender, expire_due, retry_delay
from tests.outbound_helpers import FakeResolver, TestMta
from tests.unit.fakes import make_app, make_session_factory
from tests.unit.test_messages import Person, person
from tests.unit.test_outbound import OUTBOUND, claim, mime, submission
from tests.unit.test_outbound_dkim import receiver_dns

MAIL_DOMAIN = "mail.agnusmail.localhost"


@dataclass
class FakeTransport:
    replies: dict[str, Result] = field(default_factory=dict)
    calls: list[tuple[str, str, list[str], bytes]] = field(default_factory=list)

    def deliver(
        self, domain: str, sender: str, recipients: list[str], data: bytes
    ) -> dict[str, Result]:
        self.calls.append((domain, sender, recipients, data))
        return {r: self.replies.get(r, Result(Outcome.DELIVERED, 250, "2.0.0")) for r in recipients}


@dataclass
class QueueKeyAdapter:
    """``submission`` expects an object with ``cert`` (the published certificate)."""

    key: QueueKey

    @property
    def cert(self) -> Any:
        import pysequoia

        return pysequoia.Cert.from_bytes(self.key.certificate)


@pytest.fixture(scope="module")
def queue_key() -> QueueKey:
    return load_queue_key(generate_queue_key(), now=datetime.now(UTC))


@pytest.fixture(scope="module")
def signer() -> DkimSigner:
    return DkimSigner(MAIL_DOMAIN, "agnus1", generate_dkim_key())


@pytest.fixture
def factory(queue_key: QueueKey) -> sessionmaker[Session]:
    factory = make_session_factory()
    with factory() as session, session.begin():
        assert register_queue_key(session, queue_key)
        assert not register_queue_key(session, queue_key)  # idempotent
    return factory


@dataclass
class Sender:
    person: Person
    address: str


@pytest.fixture
def alice(factory: sessionmaker[Session]) -> Iterator[Sender]:
    p = person(make_app(session_factory=factory)[0])
    yield Sender(p, claim(p))
    p.client.close()


def submit(alice: Sender, key: QueueKey, recipients: list[str], body: bytes | None = None) -> str:
    payload = submission(QueueKeyAdapter(key), body or mime(alice.address), recipients)
    response = alice.person.client.post(OUTBOUND, json=payload)
    assert response.status_code == 202, response.text
    return str(response.json()["id"])


def worker(
    factory: sessionmaker[Session], key: QueueKey, signer: DkimSigner, transport: Any
) -> OutboundSender:
    return OutboundSender(
        factory, keys=[key], signer=signer, transport=transport, mail_domain=MAIL_DOMAIN
    )


def state(
    factory: sessionmaker[Session], outbound_id: str
) -> tuple[OutboundMessage, dict[str, OutboundRecipient]]:
    with factory() as session:
        row = session.get(OutboundMessage, uuid.UUID(outbound_id))
        assert row is not None
        recipients = session.scalars(
            select(OutboundRecipient).where(OutboundRecipient.outbound_message_id == row.id)
        ).all()
        return row, {r.address: r for r in recipients}


def test_delivered_message_is_signed_and_erased(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    outbound_id = submit(alice, queue_key, ["b@example.org", "c@example.net"])
    transport = FakeTransport()
    now = datetime.now(UTC)
    assert worker(factory, queue_key, signer, transport).run_once(now) == 1

    assert sorted(call[0] for call in transport.calls) == ["example.net", "example.org"]
    data = transport.calls[0][3]
    assert dkim.verify(data, dnsfunc=receiver_dns(signer.private_key, domain=MAIL_DOMAIN))
    assert transport.calls[0][1] == alice.address

    row, recipients = state(factory, outbound_id)
    assert (row.status, row.payload, row.attempts) == ("done", None, 1)
    assert row.finished_at is not None
    assert {r.status for r in recipients.values()} == {"delivered"}
    # Status for the user: codes only.
    status = alice.person.client.get(f"{OUTBOUND}/{outbound_id}").json()
    assert status["status"] == "done"
    assert status["recipients"][0]["smtp_code"] == 250


def test_temporary_failures_are_retried_with_backoff(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    outbound_id = submit(alice, queue_key, ["ok@example.org", "later@example.org"])
    transport = FakeTransport({"later@example.org": Result(Outcome.RETRY, 451, "4.2.0")})
    now = datetime.now(UTC)
    sender = worker(factory, queue_key, signer, transport)
    sender.run_once(now)
    row, recipients = state(factory, outbound_id)
    assert row.status == "queued" and row.payload is not None
    assert recipients["ok@example.org"].status == "delivered"
    assert recipients["later@example.org"].status == "pending"
    assert recipients["later@example.org"].smtp_code == 451
    assert row.next_attempt_at.replace(tzinfo=UTC) == now + retry_delay(1)

    # Not due yet: nothing happens.
    assert sender.run_once(now + timedelta(minutes=1)) == 0
    # Due: only the pending recipient is attempted.
    transport.replies.clear()
    assert sender.run_once(now + retry_delay(1)) == 1
    assert transport.calls[-1][2] == ["later@example.org"]
    row, recipients = state(factory, outbound_id)
    assert (row.status, row.payload, row.attempts) == ("done", None, 2)


def test_permanent_failures_finish_the_message(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    outbound_id = submit(alice, queue_key, ["reject@example.org"])
    transport = FakeTransport({"reject@example.org": Result(Outcome.FAILED, 550, "5.1.1")})
    worker(factory, queue_key, signer, transport).run_once(datetime.now(UTC))
    row, recipients = state(factory, outbound_id)
    assert (row.status, row.payload) == ("done", None)
    assert (
        recipients["reject@example.org"].status,
        recipients["reject@example.org"].smtp_status,
    ) == (
        "failed",
        "5.1.1",
    )


def test_from_must_be_the_sender(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    forged = mime("ceo@bank.example")
    outbound_id = submit(alice, queue_key, ["b@example.org"], forged)
    transport = FakeTransport()
    worker(factory, queue_key, signer, transport).run_once(datetime.now(UTC))
    assert transport.calls == []  # nothing left the service
    row, recipients = state(factory, outbound_id)
    assert (row.status, row.payload) == ("done", None)
    assert recipients["b@example.org"].smtp_status == "policy_from_not_sender"


def test_messages_are_claimed_only_by_holders_of_their_key(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    outbound_id = submit(alice, queue_key, ["b@example.org"])
    other = load_queue_key(generate_queue_key(), now=datetime.now(UTC))
    transport = FakeTransport()
    now = datetime.now(UTC)
    # An instance without the key (rotated away, misconfigured) leaves it untouched...
    assert worker(factory, other, signer, transport).run_once(now) == 0
    row, recipients = state(factory, outbound_id)
    assert (row.status, row.attempts, row.locked_until) == ("queued", 0, None)
    assert transport.calls == []
    # ...for an instance that holds it (current plus previous keys).
    both = OutboundSender(
        factory,
        keys=[other, queue_key],
        signer=signer,
        transport=transport,
        mail_domain=MAIL_DOMAIN,
    )
    assert both.run_once(now) == 1
    assert state(factory, outbound_id)[0].status == "done"


def test_expiry_erases_the_ciphertext_at_72h(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    outbound_id = submit(alice, queue_key, ["later@example.org"])
    row, _ = state(factory, outbound_id)
    created = row.created_at.replace(tzinfo=UTC)
    assert row.expires_at.replace(tzinfo=UTC) - created < QUEUE_LIMIT
    transport = FakeTransport({"later@example.org": Result(Outcome.RETRY, 451, "4.2.0")})
    sender = worker(factory, queue_key, signer, transport)
    sender.run_once(datetime.now(UTC))
    sender.run_once(created + QUEUE_LIMIT)
    row, recipients = state(factory, outbound_id)
    assert (row.status, row.payload) == ("expired", None)
    assert (
        recipients["later@example.org"].status,
        recipients["later@example.org"].smtp_status,
    ) == (
        "failed",
        "expired",
    )


def test_worker_purge_job_expires_without_the_service(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey
) -> None:
    outbound_id = submit(alice, queue_key, ["b@example.org"])
    with factory() as session, session.begin():
        assert expire_due(session, datetime.now(UTC)) == 0
        assert expire_due(session, datetime.now(UTC) + QUEUE_LIMIT) == 1
    row, _ = state(factory, outbound_id)
    assert (row.status, row.payload) == ("expired", None)


def test_purge_job_deletes_old_records(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    from agnusmail.modules.jobs.handlers import purge_outbound
    from agnusmail.modules.jobs.queue import JobContext
    from tests.unit.fakes import make_settings

    outbound_id = submit(alice, queue_key, ["b@example.org"])
    worker(factory, queue_key, signer, FakeTransport()).run_once(datetime.now(UTC))
    with factory() as session, session.begin():
        row = session.get(OutboundMessage, uuid.UUID(outbound_id))
        assert row is not None
        row.finished_at = datetime.now(UTC) - timedelta(days=31)
    purge_outbound(JobContext(factory=factory, settings=make_settings()), {})
    with factory() as session:
        assert session.get(OutboundMessage, uuid.UUID(outbound_id)) is None
        assert session.scalars(select(OutboundRecipient)).all() == []


def test_a_claimed_message_is_not_claimed_again(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    submit(alice, queue_key, ["b@example.org"])
    sender = worker(factory, queue_key, signer, FakeTransport())
    now = datetime.now(UTC)
    claimed = sender._claim(now)
    assert len(claimed) == 1
    assert sender._claim(now) == []  # leased
    assert len(sender._claim(now + timedelta(minutes=11))) == 1  # lease expired


def test_a_crashing_transport_retries(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    class Broken:
        def deliver(self, *_args: Any) -> dict[str, Result]:
            raise RuntimeError("bug")

    outbound_id = submit(alice, queue_key, ["b@example.org"])
    worker(factory, queue_key, signer, Broken()).run_once(datetime.now(UTC))
    row, recipients = state(factory, outbound_id)
    assert row.status == "queued"
    assert recipients["b@example.org"].smtp_status == "internal_error"


def test_end_to_end_to_a_real_smtp_server(
    factory: sessionmaker[Session], alice: Sender, queue_key: QueueKey, signer: DkimSigner
) -> None:
    mta = TestMta()
    mta.start()
    try:
        outbound_id = submit(
            alice, queue_key, ["b@example.org", "reject@example.org", "later@example.org"]
        )
        transport = SmtpDelivery(
            hostname="out.example.com", resolver=FakeResolver(), relay=mta.relay
        )
        worker(factory, queue_key, signer, transport).run_once(datetime.now(UTC))
    finally:
        mta.stop()
    [received] = mta.recorder.received
    assert received.recipients == ["b@example.org"]
    assert received.mail_from == alice.address
    assert dkim.verify(
        received.content, dnsfunc=receiver_dns(signer.private_key, domain=MAIL_DOMAIN)
    )
    assert b"TEST-ONLY body" in received.content
    _, recipients = state(factory, outbound_id)
    assert {a: r.status for a, r in recipients.items()} == {
        "b@example.org": "delivered",
        "reject@example.org": "failed",
        "later@example.org": "pending",
    }


def test_retry_delay_is_capped() -> None:
    assert retry_delay(1) == timedelta(minutes=5)
    assert retry_delay(2) == timedelta(minutes=10)
    assert retry_delay(20) == timedelta(hours=3)
