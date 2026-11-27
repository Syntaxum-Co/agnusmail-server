"""Secure portal (protocol v1 §11).

Envelopes: the PKESKs and the SEIPDv2 are real (Sequoia, to the sender's published
keys, so the sender can open their copy). Sequoia writes password packets with the
iterated S2K, not Argon2, so the SKESK comes from the OpenPGP.js v7 vector
(``tests/vectors/recovery_backup_openpgpjs.pgp``) with its Argon2 passes raised to the
portal's t = 3. The server only reads headers, so this tests exactly what it checks; a
decryptable OpenPGP.js portal vector is pending (spec §14, group 6).
"""

import base64
import hashlib
import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pysequoia
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.infrastructure.openpgp import TAG_SKESK, packet_tag, split_packets
from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.messages.models import Message, MessageOrigin
from agnusmail.modules.outbound.models import OutboundMessage
from agnusmail.modules.portal.models import PortalLink, PortalMessage
from agnusmail.testing.fakes import make_app, make_session_factory, make_settings
from agnusmail.testing.openpgp import DeviceKeys, encrypt_split, new_device
from agnusmail.testing.people import Person, person, published
from tests.unit.test_outbound import claim, register_outbound_key

PORTAL = "/v1/portal"
BASE_URL = "https://app.example.com/portal"
VECTOR = Path(__file__).resolve().parents[1] / "vectors" / "recovery_backup_openpgpjs.pgp"
PLAINTEXT = b"Subject: contract\r\n\r\nTEST-ONLY portal body\r\n"


def skesk(passes: int = 3) -> bytes:
    """The OpenPGP.js SKESK v6 (Argon2, AES-256, OCB) with ``passes`` as Argon2 t."""
    packet = next(p for p in split_packets(VECTOR.read_bytes()) if packet_tag(p) == TAG_SKESK)
    header = 2 if packet[1] < 192 else 3
    patched = bytearray(packet)
    patched[header + 22] = passes
    return bytes(patched)


def own_certs(sender: Person) -> list[Any]:
    keys = published(sender.client, sender.user.address)
    return [pysequoia.Cert.from_bytes(base64.b64decode(k["material"])) for k in keys]


def envelope(sender: Person, *, passes: int = 3, certs: list[Any] | None = None) -> bytes:
    pkesks, body = encrypt_split(PLAINTEXT, certs or own_certs(sender), sender.keys)
    return b"".join(pkesks) + skesk(passes) + body


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def request(sender: Person, recipients: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "message_id": secrets.token_hex(16),
        "recipients": recipients or ["friend@example.org"],
        "expires_in_days": 7,
        "envelope": b64(envelope(sender)),
        **extra,
    }


def token_of(url: str) -> str:
    base, _, token = url.partition("#")
    assert base == BASE_URL
    return token


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return make_app(make_settings(portal_base_url=BASE_URL), session_factory=factory)[0]


@pytest.fixture
def queue(factory: sessionmaker[Session]) -> DeviceKeys:
    return register_outbound_key(factory)


@pytest.fixture
def alice(app: Any) -> Iterator[Person]:
    p = person(app)
    claim(p)
    yield p
    p.client.close()


@pytest.fixture
def anonymous(app: Any) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def create(alice: Person, **extra: Any) -> dict[str, Any]:
    response = alice.client.post(f"{PORTAL}/messages", json=request(alice, **extra))
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


def test_create_returns_links_once_and_queues_notices(
    alice: Person, queue: DeviceKeys, factory: sessionmaker[Session]
) -> None:
    data = create(alice, recipients=["Friend@Example.org", "other@example.net"])
    assert data["protection"] == "e2ee-shared-secret"
    tokens = {link["recipient"]: token_of(link["url"]) for link in data["links"]}
    assert set(tokens) == {"Friend@example.org", "other@example.net"}
    assert all(len(t) == 43 for t in tokens.values())
    with factory() as session:
        links = session.scalars(select(PortalLink)).all()
        stored = {link.token_hash for link in links}
        assert stored == {hashlib.sha256(t.encode()).hexdigest() for t in tokens.values()}
        assert not any(t in str(link.__dict__) for t in tokens.values() for link in links)
        notices = session.scalars(select(OutboundMessage)).all()
        assert sorted(n.kind for n in notices) == ["portal_notice", "portal_notice"]
        for notice in notices:
            assert notice.payload is not None
            opened = pysequoia.decrypt(decryptor=queue.tsk.decryptor(), bytes=notice.payload)
            text = bytes(opened.bytes or b"")
            assert b"TEST-ONLY" not in text  # never the message
            assert b"Subject: Encrypted message from " in text
            assert any(t.encode() in text for t in tokens.values())
        event = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "portal.created")
        ).one()
        assert event.details["recipients"] == 2
    # The listing never shows the tokens again.
    listed = alice.client.get(f"{PORTAL}/messages").json()["items"]
    assert "links" not in listed[0] and len(listed[0]["recipients"]) == 2


def test_without_notices_no_outbound_key_is_needed(
    alice: Person, factory: sessionmaker[Session]
) -> None:
    create(alice, notify=False)
    with factory() as session:
        assert session.scalars(select(OutboundMessage)).all() == []


def test_notices_need_the_outbound_service(alice: Person) -> None:
    response = alice.client.post(f"{PORTAL}/messages", json=request(alice))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "OUTBOUND_UNAVAILABLE"


def test_portal_disabled_without_base_url(factory: sessionmaker[Session]) -> None:
    app = make_app(session_factory=factory)[0]
    alice = person(app)
    claim(alice)
    response = alice.client.post(f"{PORTAL}/messages", json=request(alice, notify=False))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PORTAL_UNAVAILABLE"


def test_envelope_rules(alice: Person, queue: DeviceKeys) -> None:
    pkesks, body = encrypt_split(PLAINTEXT, own_certs(alice), alice.keys)
    cases = {
        "weak argon2": b"".join(pkesks) + skesk(passes=1) + body,
        "no password": b"".join(pkesks) + body,
        "two passwords": b"".join(pkesks) + skesk() + skesk() + body,
        "no seipd": b"".join(pkesks) + skesk(),
    }
    for name, bad in cases.items():
        payload = request(alice, envelope=b64(bad))
        response = alice.client.post(f"{PORTAL}/messages", json=payload)
        assert response.status_code == 422, name
        assert response.json()["error"]["code"] == "ENVELOPE_INVALID", name
    # PKESKs must be exactly the sender's published keys (they keep a readable copy).
    wrong = envelope(alice, certs=[queue.cert])
    response = alice.client.post(f"{PORTAL}/messages", json=request(alice, envelope=b64(wrong)))
    assert response.status_code == 409


@pytest.mark.parametrize(
    ("change", "status"),
    [
        ({"recipients": ["bob@mail.agnusmail.localhost"]}, 422),
        ({"expires_in_days": 31}, 422),
        ({"expires_in_days": 0}, 422),
    ],
)
def test_request_rules(
    alice: Person, queue: DeviceKeys, change: dict[str, Any], status: int
) -> None:
    response = alice.client.post(f"{PORTAL}/messages", json=request(alice, **change))
    assert response.status_code == status


def test_shorter_configured_maximum(factory: sessionmaker[Session]) -> None:
    app = make_app(
        make_settings(portal_base_url=BASE_URL, portal_max_days=3), session_factory=factory
    )[0]
    alice = person(app)
    claim(alice)
    payload = request(alice, notify=False, expires_in_days=4)
    response = alice.client.post(f"{PORTAL}/messages", json=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "PORTAL_EXPIRY_INVALID"


def test_recipient_opens_with_the_token_only(
    alice: Person, anonymous: TestClient, factory: sessionmaker[Session]
) -> None:
    data = create(alice, notify=False)
    token = token_of(data["links"][0]["url"])
    opened = anonymous.post(f"{PORTAL}/access", json={"token": token})
    assert opened.status_code == 200, opened.text
    body = opened.json()
    assert body["sender"].endswith("@mail.agnusmail.localhost")
    assert body["recipient"] == "friend@example.org"  # the link's own address (reply From)
    assert body["protection"] == "e2ee-shared-secret"
    assert body["replies_left"] == 5
    with factory() as session:
        stored = session.scalars(select(PortalMessage)).one()
        assert base64.b64decode(body["envelope"]) == stored.envelope
        assert session.scalars(select(PortalLink)).one().last_access_at is not None
    for bad in ("x" * 43, secrets.token_urlsafe(32)):
        assert anonymous.post(f"{PORTAL}/access", json={"token": bad}).status_code == 404
    assert anonymous.post(f"{PORTAL}/access", json={"token": "short"}).status_code == 422


def test_reply_reaches_the_senders_inbox(
    alice: Person, anonymous: TestClient, factory: sessionmaker[Session]
) -> None:
    data = create(alice, notify=False)
    token = token_of(data["links"][0]["url"])
    directory = anonymous.post(f"{PORTAL}/keys", json={"token": token}).json()
    assert directory["address"].lower() == alice.user.address.lower()
    entries = list(directory["keys"]) + (
        [directory["recovery_key"]] if directory.get("recovery_key") else []
    )
    certs = [pysequoia.Cert.from_bytes(base64.b64decode(k["material"])) for k in entries]
    reply_text = b"Subject: re: contract\r\n\r\nTEST-ONLY reply\r\n"
    sealed = pysequoia.encrypt(reply_text, recipients=certs, armor=False)
    *pkesks, body = split_packets(sealed)
    payload = {"token": token, "version": 1, "pkesks": [b64(p) for p in pkesks], "body": b64(body)}
    response = anonymous.post(f"{PORTAL}/replies", json=payload)
    assert response.status_code == 201, response.text
    assert response.json() == {"replies_left": 4}

    inbox = alice.client.get("/v1/messages", params={"folder": "inbox"}).json()["items"]
    assert [(m["origin"], m["sender"]) for m in inbox] == [("portal", None)]
    read = alice.client.get(f"/v1/messages/{inbox[0]['id']}").json()
    opened = pysequoia.decrypt(
        decryptor=alice.keys.tsk.decryptor(),
        bytes=base64.b64decode(read["pkesks"][0]) + base64.b64decode(read["body"]),
    )
    assert bytes(opened.bytes or b"") == reply_text
    with factory() as session:
        assert session.scalars(select(Message)).one().origin == MessageOrigin.PORTAL


def test_reply_pkesks_are_checked(alice: Person, anonymous: TestClient) -> None:
    token = token_of(create(alice, notify=False)["links"][0]["url"])
    sealed = pysequoia.encrypt(b"x", recipients=own_certs(alice), armor=False)
    *pkesks, body = split_packets(sealed)
    duplicate = {"token": token, "version": 1, "pkesks": [b64(pkesks[0])] * 2, "body": b64(body)}
    assert anonymous.post(f"{PORTAL}/replies", json=duplicate).status_code == 422
    stranger = new_device()  # not one of the sender's published keys
    sealed = pysequoia.encrypt(b"x", recipients=[stranger.cert], armor=False)
    *pkesks, body = split_packets(sealed)
    unknown = {"token": token, "version": 1, "pkesks": [b64(p) for p in pkesks], "body": b64(body)}
    assert anonymous.post(f"{PORTAL}/replies", json=unknown).status_code == 409
    # Nothing was stored and no reply was counted.
    assert alice.client.get("/v1/messages").json()["items"] == []


def test_reply_limit(factory: sessionmaker[Session]) -> None:
    app = make_app(
        make_settings(portal_base_url=BASE_URL, portal_max_replies_per_link=1),
        session_factory=factory,
    )[0]
    alice = person(app)
    claim(alice)
    token = token_of(create(alice, notify=False)["links"][0]["url"])
    sealed = pysequoia.encrypt(b"x", recipients=own_certs(alice), armor=False)
    *pkesks, body = split_packets(sealed)
    payload = {"token": token, "version": 1, "pkesks": [b64(p) for p in pkesks], "body": b64(body)}
    with TestClient(app, raise_server_exceptions=False) as anonymous:
        assert anonymous.post(f"{PORTAL}/replies", json=payload).status_code == 201
        second = anonymous.post(f"{PORTAL}/replies", json=payload)
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "REPLY_LIMIT"


def test_expiry_and_purge(
    alice: Person, anonymous: TestClient, factory: sessionmaker[Session]
) -> None:
    from agnusmail.modules.jobs.handlers import purge_portal
    from agnusmail.modules.jobs.queue import JobContext

    data = create(alice, notify=False)
    token = token_of(data["links"][0]["url"])
    with factory() as session, session.begin():
        message = session.get(PortalMessage, uuid.UUID(data["id"]))
        assert message is not None
        message.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert anonymous.post(f"{PORTAL}/access", json={"token": token}).status_code == 404
    purge_portal(JobContext(factory=factory, settings=make_settings()), {})
    with factory() as session:
        assert session.scalars(select(PortalMessage)).all() == []
        assert session.scalars(select(PortalLink)).all() == []


def test_sender_owns_and_deletes(app: Any, alice: Person, anonymous: TestClient) -> None:
    data = create(alice, notify=False)
    own = alice.client.get(f"{PORTAL}/messages/{data['id']}").json()
    copy = pysequoia.decrypt(
        decryptor=alice.keys.tsk.decryptor(), bytes=base64.b64decode(own["envelope"])
    )
    assert bytes(copy.bytes or b"") == PLAINTEXT  # the sender's copy opens with their key
    mallory = person(app)
    assert mallory.client.get(f"{PORTAL}/messages/{data['id']}").status_code == 404
    assert mallory.client.delete(f"{PORTAL}/messages/{data['id']}").status_code == 404
    assert alice.client.delete(f"{PORTAL}/messages/{data['id']}").status_code == 204
    token = token_of(data["links"][0]["url"])
    assert anonymous.post(f"{PORTAL}/access", json={"token": token}).status_code == 404


def test_access_is_rate_limited_per_ip(factory: sessionmaker[Session]) -> None:
    app = make_app(
        make_settings(portal_base_url=BASE_URL, portal_access_per_ip_per_minute=2),
        session_factory=factory,
    )[0]
    with TestClient(app, raise_server_exceptions=False) as anonymous:
        codes = [
            anonymous.post(f"{PORTAL}/access", json={"token": "a" * 43}).status_code
            for _ in range(3)
        ]
    assert codes == [404, 404, 429]
