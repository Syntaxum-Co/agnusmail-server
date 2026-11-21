"""E2EE messages between users (protocol v1 §6).

Clients are simulated end to end: devices with real OpenPGP v6 certificates, authorized
by the wallet, sessions bound to them; senders encrypt with Sequoia to the keys the
directory publishes and recipients decrypt in the test (the client's role).
"""

import base64
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pysequoia
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.infrastructure.openpgp import pkesk_recipient
from agnusmail.modules.messages.models import Message, MessageKey
from tests.openpgp_helpers import DeviceKeys, decrypt_joined, encrypt_split, new_device
from tests.unit.auth_helpers import LoggedIn, login
from tests.unit.device_helpers import Onboarded, onboard
from tests.unit.fakes import make_app, make_session_factory, make_settings

MESSAGES = "/v1/messages"
PLAINTEXT = b"From: alice@example\r\nSubject: secret plans\r\n\r\nMeet at noon.\r\n"


@dataclass
class Person:
    client: TestClient
    user: LoggedIn
    device: Onboarded

    @property
    def keys(self) -> DeviceKeys:
        return self.device.keys


def bind_session(client: TestClient, device: Onboarded) -> None:
    issued = client.post("/v1/auth/device/challenge", json={"device_id": device.device_id}).json()
    signature = base64.b64encode(device.keys.sign(issued["statement"].encode())).decode()
    response = client.post(
        "/v1/auth/device/bind", json={"device_id": device.device_id, "signature": signature}
    )
    assert response.status_code == 200, response.text


def person(app: Any) -> Person:
    client = TestClient(app, raise_server_exceptions=False)
    user = login(client)
    device = onboard(client, user)
    bind_session(client, device)
    return Person(client, user, device)


def second_device(owner: Person, app: Any) -> Person:
    """The same account on a new device (new client, own bound session)."""
    client = TestClient(app, raise_server_exceptions=False)
    login(client, owner.user.account)
    device = onboard(client, owner.user)
    bind_session(client, device)
    return Person(client, owner.user, device)


def published(client: TestClient, address: str) -> list[dict[str, Any]]:
    """Every key a sender must encrypt to: device keys plus the recovery key (§6.2)."""
    directory = client.get(f"/v1/keys/{address}").json()
    keys: list[dict[str, Any]] = list(directory["keys"])
    if directory.get("recovery_key"):
        keys.append(directory["recovery_key"])
    return keys


def compose(
    sender: Person, recipients: list[Person], *, plaintext: bytes = PLAINTEXT
) -> dict[str, Any]:
    """What a client does: fetch the directory, encrypt to every published key (own
    devices included) and route each PKESK by its recipient fingerprint."""
    accounts = {p.user.address: published(sender.client, p.user.address) for p in recipients}
    own = published(sender.client, sender.user.address)
    entries = [k for keys in accounts.values() for k in keys] + own
    certs = [pysequoia.Cert.from_bytes(base64.b64decode(k["material"])) for k in entries]
    pkesks, body = encrypt_split(plaintext, certs, sender.keys)
    by_fpr = {pkesk_recipient(p): base64.b64encode(p).decode() for p in pkesks}
    return {
        "version": 1,
        "message_id": secrets.token_hex(16),
        "recipients": [
            {"account": account, "pkesks": [by_fpr[k["encryption_fingerprint"]] for k in keys]}
            for account, keys in accounts.items()
        ],
        "self_pkesks": [by_fpr[k["encryption_fingerprint"]] for k in own],
        "body": base64.b64encode(body).decode(),
    }


def open_message(reader: Person, message_id: str, sender: Person) -> bytes:
    data = reader.client.get(f"{MESSAGES}/{message_id}").json()
    assert data["pkesks"], data
    plaintext, signatures = decrypt_joined(
        reader.keys,
        base64.b64decode(data["pkesks"][0]),
        base64.b64decode(data["body"]),
        sender.keys.cert,
    )
    assert signatures == 1  # signed by the sender's device
    return plaintext


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return make_app(session_factory=factory)[0]


@pytest.fixture
def alice(app: Any) -> Iterator[Person]:
    p = person(app)
    yield p
    p.client.close()


@pytest.fixture
def bob(app: Any) -> Iterator[Person]:
    p = person(app)
    yield p
    p.client.close()


def send(sender: Person, payload: dict[str, Any]) -> Any:
    return sender.client.post(MESSAGES, json=payload)


def test_end_to_end_message_between_users(alice: Person, bob: Person) -> None:
    payload = compose(alice, [bob])
    response = send(alice, payload)
    assert response.status_code == 201, response.text
    sent = response.json()
    assert sent["message_id"] == payload["message_id"]

    inbox = bob.client.get(MESSAGES).json()
    assert inbox["total"] == 1
    item = inbox["items"][0]
    assert (item["sender"], item["folder"], item["read"]) == (
        alice.user.address.lower(),
        "inbox",
        False,
    )
    assert open_message(bob, sent["id"], alice) == PLAINTEXT
    # The sender keeps a copy in Sent, readable by her own device.
    assert alice.client.get(MESSAGES, params={"folder": "sent"}).json()["total"] == 1
    assert open_message(alice, sent["id"], alice) == PLAINTEXT


def test_server_stores_only_ciphertext(
    alice: Person, bob: Person, factory: sessionmaker[Session]
) -> None:
    payload = compose(alice, [bob])
    message_id = send(alice, payload).json()["id"]
    with factory() as session:
        row = session.scalars(select(Message)).one()
        keys = session.scalars(select(MessageKey)).all()
    assert str(row.id) == message_id
    assert row.body == base64.b64decode(payload["body"])  # stored exactly as sent
    for blob in [row.body, *(k.pkesk for k in keys)]:
        assert b"secret plans" not in blob and b"Meet at noon" not in blob
    assert len(keys) == 2  # bob's device + alice's own device


def test_incomplete_or_outdated_recipient_keys_are_refused(
    app: Any, alice: Person, bob: Person, factory: sessionmaker[Session]
) -> None:
    payload = compose(alice, [bob])
    missing = {
        **payload,
        "recipients": [{**payload["recipients"][0], "pkesks": payload["self_pkesks"]}],
    }
    response = send(alice, missing)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "RECIPIENT_KEYS_CHANGED"

    # Bob adds a device after Alice fetched the directory: her message is now incomplete.
    newer = second_device(bob, app)
    try:
        response = send(alice, payload)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "RECIPIENT_KEYS_CHANGED"
        fresh = compose(alice, [bob])
        assert len(fresh["recipients"][0]["pkesks"]) == 2
        assert send(alice, fresh).status_code == 201
        assert open_message(newer, newer.client.get(MESSAGES).json()["items"][0]["id"], alice)
    finally:
        newer.client.close()
    with factory() as session:
        assert len(session.scalars(select(Message)).all()) == 1  # refused ones left nothing


@pytest.mark.parametrize(
    "damage",
    ["cipher", "armor", "two_packets", "pkesk_version", "garbage_pkesk"],
)
def test_malformed_envelopes_are_refused(alice: Person, bob: Person, damage: str) -> None:
    payload = compose(alice, [bob])
    body = base64.b64decode(payload["body"])
    pkesk = base64.b64decode(payload["recipients"][0]["pkesks"][0])
    if damage == "cipher":
        raw = bytearray(body)
        # SEIPDv2 header right after the packet header: version 2, cipher 9, AEAD 2.
        raw[raw.index(bytes([2, 9, 2])) + 1] = 7  # AES-256 (9) -> AES-128 (7)
        payload["body"] = base64.b64encode(bytes(raw)).decode()
    elif damage == "armor":
        payload["body"] = base64.b64encode(b"-----BEGIN PGP MESSAGE-----\n").decode()
    elif damage == "two_packets":
        payload["body"] = base64.b64encode(body + body).decode()
    elif damage == "pkesk_version":
        raw = bytearray(pkesk)
        raw[raw.index(bytes([6, 33, 6]))] = 3
        payload["recipients"][0]["pkesks"] = [base64.b64encode(bytes(raw)).decode()]
    else:
        payload["recipients"][0]["pkesks"] = [base64.b64encode(b"\x01\x02\x03").decode()]
    response = send(alice, payload)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "ENVELOPE_INVALID"


def test_message_ids_cannot_be_reused(alice: Person, bob: Person) -> None:
    payload = compose(alice, [bob])
    assert send(alice, payload).status_code == 201
    replay = send(alice, payload)
    assert replay.status_code == 409 and replay.json()["error"]["code"] == "CONFLICT"


def test_recipient_rules(alice: Person, bob: Person) -> None:
    payload = compose(alice, [bob])
    for recipients, code in (
        ([{**payload["recipients"][0], "account": "0x" + "12" * 20}], "RECIPIENT_INVALID"),
        ([{**payload["recipients"][0], "account": alice.user.address}], "RECIPIENT_INVALID"),
        ([payload["recipients"][0], payload["recipients"][0]], "RECIPIENT_INVALID"),
    ):
        response = send(alice, {**payload, "recipients": recipients})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == code
    for broken in (
        {**payload, "version": 2},
        {**payload, "message_id": "XYZ"},
        {**payload, "body": "@@"},
    ):
        assert send(alice, broken).status_code == 422


def test_limits() -> None:
    app, _ = make_app(make_settings(max_message_bytes=1024, max_message_recipients=1))
    sender, first, second = person(app), person(app), person(app)
    try:
        too_many = compose(sender, [first, second])
        assert send(sender, too_many).json()["error"]["code"] == "RECIPIENT_INVALID"
        big = compose(sender, [first], plaintext=secrets.token_bytes(4096))
        response = send(sender, big)
        assert response.status_code == 422 and "exceeds" in response.json()["error"]["detail"]
    finally:
        for p in (sender, first, second):
            p.client.close()


def test_messages_need_a_device_bound_session(app: Any, alice: Person, bob: Person) -> None:
    payload = compose(alice, [bob])
    with TestClient(app, raise_server_exceptions=False) as unbound:
        login(unbound, alice.user.account)
        for response in (unbound.post(MESSAGES, json=payload), unbound.get(MESSAGES)):
            assert response.status_code == 403
            assert response.json()["error"]["code"] == "DEVICE_SESSION_REQUIRED"


def test_other_users_cannot_touch_a_message(app: Any, alice: Person, bob: Person) -> None:
    message_id = send(alice, compose(alice, [bob])).json()["id"]
    carol = person(app)
    try:
        for method, path, body in (
            ("get", f"{MESSAGES}/{message_id}", None),
            ("post", f"{MESSAGES}/{message_id}/read", None),
            ("post", f"{MESSAGES}/{message_id}/move", {"folder": "trash"}),
            ("post", f"{MESSAGES}/{message_id}/keys", {"pkesks": ["AAAA"]}),
        ):
            response = (
                getattr(carol.client, method)(path, json=body)
                if body
                else getattr(carol.client, method)(path)
            )
            assert response.status_code == 404, (path, response.text)
        assert carol.client.get(MESSAGES).json()["total"] == 0
    finally:
        carol.client.close()


def test_fixed_folders_and_read_state(alice: Person, bob: Person) -> None:
    message_id = send(alice, compose(alice, [bob])).json()["id"]
    assert bob.client.post(f"{MESSAGES}/{message_id}/read").json() == {
        "folder": "inbox",
        "folder_id": None,
        "read": True,
    }
    assert bob.client.post(f"{MESSAGES}/{message_id}/read").json()["read"] is True  # idempotent
    trash = bob.client.post(f"{MESSAGES}/{message_id}/move", json={"folder": "trash"})
    assert trash.json()["folder"] == "trash"
    assert bob.client.get(MESSAGES, params={"folder": "trash"}).json()["total"] == 1
    wrong = bob.client.post(f"{MESSAGES}/{message_id}/move", json={"folder": "sent"})
    assert wrong.status_code == 409  # a recipient's copy belongs in inbox or trash
    assert (
        bob.client.post(f"{MESSAGES}/{message_id}/move", json={"folder": "inbox"}).status_code
        == 200
    )
    assert (
        alice.client.post(f"{MESSAGES}/{message_id}/move", json={"folder": "inbox"}).status_code
        == 409
    )
    assert (
        bob.client.post(f"{MESSAGES}/{message_id}/move", json={"folder": "spam"}).status_code == 422
    )


def test_history_can_be_shared_with_a_new_device(app: Any, alice: Person, bob: Person) -> None:
    message_id = send(alice, compose(alice, [bob])).json()["id"]
    newer = second_device(bob, app)
    try:
        assert newer.client.get(f"{MESSAGES}/{message_id}").json()["pkesks"] == []
        # A device holding the session key wraps it for the new device's published key.
        # (Here the PKESK comes from a fresh encryption: the server only checks routing.)
        pkesks, _ = encrypt_split(b"x", [newer.keys.cert], bob.keys)
        payload = {"pkesks": [base64.b64encode(pkesks[0]).decode()]}
        shared = bob.client.post(f"{MESSAGES}/{message_id}/keys", json=payload)
        assert shared.status_code == 200 and shared.json() == {"added": 1}
        assert len(newer.client.get(f"{MESSAGES}/{message_id}").json()["pkesks"]) == 1
        again = bob.client.post(f"{MESSAGES}/{message_id}/keys", json=payload)
        assert again.status_code == 409
        foreign, _ = encrypt_split(b"x", [new_device().cert], bob.keys)
        response = bob.client.post(
            f"{MESSAGES}/{message_id}/keys",
            json={"pkesks": [base64.b64encode(foreign[0]).decode()]},
        )
        assert response.status_code == 409  # not one of Bob's published keys
    finally:
        newer.client.close()
