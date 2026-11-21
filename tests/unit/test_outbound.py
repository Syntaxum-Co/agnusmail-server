"""Submission to the outbound queue (protocol v1 §10).

The client encrypts the ready MIME message to the outbound service's key; the API checks
structure, recipients and limits and queues the ciphertext for at most 72 h. Every
response labels the channel ``not-e2ee``.
"""

import base64
import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pysequoia
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.messages.models import Message, MessageOrigin
from agnusmail.modules.outbound.models import (
    QUEUE_TTL,
    OutboundKey,
    OutboundMessage,
    OutboundRecipient,
)
from agnusmail.modules.outbound.recipients import (
    InvalidRecipientError,
    is_internal,
    normalize_recipient,
)
from agnusmail.testing.fakes import make_app, make_session_factory, make_settings
from agnusmail.testing.openpgp import DeviceKeys, encrypt_split, new_device
from agnusmail.testing.people import Person, person, published

OUTBOUND = "/v1/outbound/messages"
MAIL_DOMAIN = "mail.agnusmail.localhost"


def mime(sender: str, to: str = "friend@example.org") -> bytes:
    return (
        f"From: {sender}\r\nTo: {to}\r\nSubject: hello\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n"
        "TEST-ONLY body\r\n"
    ).encode()


def register_outbound_key(factory: sessionmaker[Session], **fields: Any) -> DeviceKeys:
    """What the outbound service does at startup: publish its queue certificate."""
    keys = new_device()
    encryption = next(
        str(k.fingerprint).lower()
        for k in pysequoia.packet.PacketPile.from_bytes(bytes(keys.cert))
        if k.tag == pysequoia.packet.Tag.PublicSubkey
        and k.key_algorithm == pysequoia.packet.PublicKeyAlgorithm.MLKEM768_X25519
    )
    with factory() as session, session.begin():
        session.add(
            OutboundKey(
                fingerprint=keys.fingerprint,
                encryption_fingerprint=encryption,
                material=bytes(keys.cert),
                expires_at=fields.get("expires_at", datetime.now(UTC) + timedelta(days=300)),
            )
        )
    return keys


def claim(p: Person) -> str:
    name = "u" + secrets.token_hex(5)
    response = p.client.post("/v1/addresses", json={"local_part": name})
    assert response.status_code == 201, response.text
    return f"{name}@{MAIL_DOMAIN}"


def encrypt_to(cert: Any, plaintext: bytes) -> bytes:
    data: bytes = pysequoia.encrypt(plaintext, recipients=[cert], armor=False)
    return data


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def submission(
    queue: Any,  # anything with ``cert``: the published queue certificate
    plaintext: bytes,
    recipients: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "version": 1,
        "message_id": secrets.token_hex(16),
        "recipients": recipients or ["friend@example.org"],
        "payload": b64(encrypt_to(queue.cert, plaintext)),
        **extra,
    }


def sent_copy(sender: Person, plaintext: bytes) -> dict[str, Any]:
    own = published(sender.client, sender.user.address)
    certs = [pysequoia.Cert.from_bytes(base64.b64decode(k["material"])) for k in own]
    pkesks, body = encrypt_split(plaintext, certs, sender.keys)
    return {"pkesks": [b64(p) for p in pkesks], "body": b64(body)}


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def made(factory: sessionmaker[Session]) -> Any:
    return make_app(session_factory=factory)


@pytest.fixture
def app(made: Any) -> Any:
    return made[0]


@pytest.fixture
def queue(factory: sessionmaker[Session]) -> DeviceKeys:
    return register_outbound_key(factory)


@pytest.fixture
def alice(app: Any) -> Iterator[Person]:
    p = person(app)
    yield p
    p.client.close()


@pytest.fixture
def sender(alice: Person) -> str:
    return claim(alice)


def test_keys_are_public_and_labelled(app: Any, queue: DeviceKeys) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app) as anonymous:
        data = anonymous.get("/v1/outbound/keys").json()
    assert data["protection"] == "not-e2ee"
    assert [k["fingerprint"] for k in data["items"]] == [queue.fingerprint]
    assert base64.b64decode(data["items"][0]["material"]) == bytes(queue.cert)


def test_expired_keys_are_not_offered(app: Any, factory: sessionmaker[Session]) -> None:
    register_outbound_key(factory, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    from fastapi.testclient import TestClient

    with TestClient(app) as anonymous:
        assert anonymous.get("/v1/outbound/keys").json()["items"] == []


def test_submission_is_queued_encrypted_and_labelled(
    alice: Person, sender: str, queue: DeviceKeys, factory: sessionmaker[Session]
) -> None:
    plaintext = mime(sender)
    payload = submission(queue, plaintext, ["Friend@Example.ORG", "other@example.net"])
    response = alice.client.post(OUTBOUND, json=payload)
    assert response.status_code == 202, response.text
    data = response.json()
    assert data["protection"] == "not-e2ee"
    assert data["status"] == "queued"
    assert data["kind"] == "message"
    assert [r["address"] for r in data["recipients"]] == ["Friend@example.org", "other@example.net"]
    assert {r["status"] for r in data["recipients"]} == {"pending"}
    created = datetime.fromisoformat(data["created_at"])
    assert datetime.fromisoformat(data["expires_at"]) - created == QUEUE_TTL

    with factory() as session:
        row = session.get(OutboundMessage, uuid.UUID(data["id"]))
        assert row is not None and row.payload is not None
        assert row.sender_address == sender
        # Only the queue key opens it (the outbound service's role).
        opened = pysequoia.decrypt(decryptor=queue.tsk.decryptor(), bytes=row.payload)
        assert bytes(opened.bytes or b"") == plaintext
        assert plaintext not in row.payload
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "outbound.submitted")
        ).all()
        assert len(events) == 1
        assert events[0].details["recipients"] == 2
        assert "friend" not in str(events[0].details).lower()  # counts only


def test_sent_copy_is_e2ee_and_in_sent(
    alice: Person, sender: str, queue: DeviceKeys, factory: sessionmaker[Session]
) -> None:
    plaintext = mime(sender)
    payload = submission(queue, plaintext, sent_copy=sent_copy(alice, plaintext))
    assert alice.client.post(OUTBOUND, json=payload).status_code == 202
    sent = alice.client.get("/v1/messages", params={"folder": "sent"}).json()["items"]
    assert [(m["origin"], m["message_id"]) for m in sent] == [("outbound", payload["message_id"])]
    with factory() as session:
        stored = session.scalars(select(Message)).one()
        assert stored.origin == MessageOrigin.OUTBOUND
    opened = alice.client.get(f"/v1/messages/{sent[0]['id']}").json()
    result = pysequoia.decrypt(
        decryptor=alice.keys.tsk.decryptor(),
        bytes=base64.b64decode(opened["pkesks"][0]) + base64.b64decode(opened["body"]),
    )
    assert bytes(result.bytes or b"") == plaintext
    # The sent copy stays in Sent (or trash), never the inbox.
    moved = alice.client.post(f"/v1/messages/{sent[0]['id']}/move", json={"folder": "inbox"})
    assert moved.status_code == 409


def test_incomplete_sent_copy_queues_nothing(
    alice: Person, sender: str, queue: DeviceKeys, factory: sessionmaker[Session]
) -> None:
    plaintext = mime(sender)
    copy = sent_copy(alice, plaintext)
    # Encrypted to a key that is not one of the sender's published keys.
    copy["pkesks"] = [b64(encrypt_split(plaintext, [queue.cert], alice.keys)[0][0])]
    response = alice.client.post(OUTBOUND, json=submission(queue, plaintext, sent_copy=copy))
    assert response.status_code == 409
    with factory() as session:
        assert session.scalars(select(OutboundMessage)).all() == []


def test_an_address_is_required(alice: Person, queue: DeviceKeys) -> None:
    response = alice.client.post(OUTBOUND, json=submission(queue, mime("x@example.org")))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SENDER_ADDRESS_REQUIRED"


@pytest.mark.parametrize(
    ("recipients", "code"),
    [
        ([f"bob@{MAIL_DOMAIN}"], "RECIPIENT_INTERNAL"),
        ([f"bob@eu.{MAIL_DOMAIN}"], "RECIPIENT_INTERNAL"),
        (["not-an-address"], "RECIPIENT_INVALID"),
        (["a@[127.0.0.1]"], "RECIPIENT_INVALID"),
        (['"quoted"@example.org'], "RECIPIENT_INVALID"),
        (["x@example.org", "X@EXAMPLE.org"], "RECIPIENT_INVALID"),
        (["ação@example.org"], "RECIPIENT_INVALID"),
    ],
)
def test_recipients_are_checked(
    alice: Person, sender: str, queue: DeviceKeys, recipients: list[str], code: str
) -> None:
    response = alice.client.post(OUTBOUND, json=submission(queue, mime(sender), recipients))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == code


def test_recipient_count_is_limited(factory: sessionmaker[Session]) -> None:
    app, _ = make_app(make_settings(outbound_max_recipients=2), session_factory=factory)
    queue = register_outbound_key(factory)
    alice = person(app)
    sender = claim(alice)
    many = ["a@example.org", "b@example.org", "c@example.org"]
    response = alice.client.post(OUTBOUND, json=submission(queue, mime(sender), many))
    assert response.status_code == 422


def test_payload_must_be_for_the_queue_key(alice: Person, sender: str, queue: DeviceKeys) -> None:
    other = new_device()
    payload = submission(queue, mime(sender))
    payload["payload"] = b64(encrypt_to(other.cert, mime(sender)))
    response = alice.client.post(OUTBOUND, json=payload)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "OUTBOUND_KEY_CHANGED"


def test_without_a_queue_key_outbound_is_unavailable(alice: Person, sender: str) -> None:
    payload = submission(new_device(), mime(sender))
    response = alice.client.post(OUTBOUND, json=payload)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "OUTBOUND_UNAVAILABLE"


def test_malformed_payloads_are_refused(alice: Person, sender: str, queue: DeviceKeys) -> None:
    two_keys: bytes = pysequoia.encrypt(
        mime(sender), recipients=[queue.cert, alice.keys.cert], armor=False
    )
    with_password: bytes = pysequoia.encrypt(
        mime(sender), recipients=[queue.cert], passwords=["pw"], armor=False
    )
    seipd_only = encrypt_split(mime(sender), [queue.cert], alice.keys)[1]
    for bad in (two_keys, with_password, seipd_only, b"\x00garbage"):
        payload = submission(queue, mime(sender))
        payload["payload"] = b64(bad)
        response = alice.client.post(OUTBOUND, json=payload)
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "ENVELOPE_INVALID"


def test_payload_size_is_limited(factory: sessionmaker[Session]) -> None:
    app, _ = make_app(make_settings(outbound_max_message_bytes=2048), session_factory=factory)
    queue = register_outbound_key(factory)
    alice = person(app)
    sender = claim(alice)
    big = mime(sender) + b"x" * 4096
    response = alice.client.post(OUTBOUND, json=submission(queue, big))
    assert response.status_code == 422


def test_message_id_is_single_use(alice: Person, sender: str, queue: DeviceKeys) -> None:
    payload = submission(queue, mime(sender))
    assert alice.client.post(OUTBOUND, json=payload).status_code == 202
    assert alice.client.post(OUTBOUND, json=payload).status_code == 409


def test_hourly_message_limit(factory: sessionmaker[Session]) -> None:
    app, _ = make_app(make_settings(outbound_messages_per_hour=2), session_factory=factory)
    queue = register_outbound_key(factory)
    alice = person(app)
    sender = claim(alice)
    codes = [
        alice.client.post(OUTBOUND, json=submission(queue, mime(sender))).status_code
        for _ in range(3)
    ]
    assert codes == [202, 202, 429]


def test_daily_recipient_limit(factory: sessionmaker[Session]) -> None:
    app, _ = make_app(make_settings(outbound_recipients_per_day=3), session_factory=factory)
    queue = register_outbound_key(factory)
    alice = person(app)
    sender = claim(alice)
    two = ["a@example.org", "b@example.org"]
    first = alice.client.post(OUTBOUND, json=submission(queue, mime(sender), two))
    second = alice.client.post(OUTBOUND, json=submission(queue, mime(sender), two))
    assert (first.status_code, second.status_code) == (202, 429)


def test_limits_fail_closed(app: Any, alice: Person, sender: str, queue: DeviceKeys) -> None:
    async def broken(*_args: Any) -> bool:
        raise ConnectionError("redis down")

    app.state.rate_limiter.consume = broken
    response = alice.client.post(OUTBOUND, json=submission(queue, mime(sender)))
    assert response.status_code == 503


def test_a_device_bound_session_is_required(app: Any, queue: DeviceKeys) -> None:
    from fastapi.testclient import TestClient

    from agnusmail.testing.auth import login

    with TestClient(app) as client:
        login(client)
        response = client.post(OUTBOUND, json=submission(queue, mime("a@example.org")))
    assert response.status_code in (401, 403)


def test_status_is_owner_only(app: Any, alice: Person, sender: str, queue: DeviceKeys) -> None:
    created = alice.client.post(OUTBOUND, json=submission(queue, mime(sender))).json()
    listed = alice.client.get(OUTBOUND).json()["items"]
    assert [m["id"] for m in listed] == [created["id"]]
    assert alice.client.get(f"{OUTBOUND}/{created['id']}").json()["status"] == "queued"
    mallory = person(app)
    assert mallory.client.get(f"{OUTBOUND}/{created['id']}").status_code == 404
    assert mallory.client.get(OUTBOUND).json()["items"] == []


def test_recipient_rows(alice: Person, sender: str, queue: DeviceKeys, factory: Any) -> None:
    alice.client.post(OUTBOUND, json=submission(queue, mime(sender), ["a@example.org"]))
    with factory() as session:
        rows = session.scalars(select(OutboundRecipient)).all()
        assert [(r.address, r.status, r.smtp_code) for r in rows] == [
            ("a@example.org", "pending", None)
        ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Bob@Example.COM", "Bob@example.com"),
        (" a.b+tag@sub.example.org ", "a.b+tag@sub.example.org"),
    ],
)
def test_normalize_recipient(raw: str, expected: str) -> None:
    assert normalize_recipient(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "@example.org",
        "a@",
        "a..b@example.org",
        ".a@example.org",
        "a@example",
        "a@-x.example.org",
        "a@example.123",
        "a" * 65 + "@example.org",
        "a@" + "b" * 250 + ".org",
        "a b@example.org",
        "a@exa_mple.org",
    ],
)
def test_malformed_recipients(raw: str) -> None:
    with pytest.raises(InvalidRecipientError):
        normalize_recipient(raw)


def test_internal_domain_and_subdomains() -> None:
    assert is_internal("a@mail.example.com", "mail.example.com")
    assert is_internal("a@x.mail.example.com", "mail.example.com")
    assert not is_internal("a@evilmail.example.com", "mail.example.com")
    assert not is_internal("a@example.com", "mail.example.com")


def test_send_from_an_alias(
    alice: Person, sender: str, queue: DeviceKeys, factory: sessionmaker[Session]
) -> None:
    created = alice.client.post("/v1/addresses/aliases", json={"local_part": "shop" + sender[1:6]})
    assert created.status_code == 201, created.text
    shop = created.json()["email"]
    response = alice.client.post(OUTBOUND, json=submission(queue, mime(shop), sender=shop))
    assert response.status_code == 202, response.text
    assert response.json()["sender"] == shop
    # Disabled aliases and other people's addresses cannot be used.
    alice.client.post(f"/v1/addresses/{created.json()['id']}/disable")
    refused = alice.client.post(OUTBOUND, json=submission(queue, mime(shop), sender=shop))
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "SENDER_INVALID"
    stranger = alice.client.post(
        OUTBOUND, json=submission(queue, mime(sender), sender="ceo@example.org")
    )
    assert stranger.status_code == 422
