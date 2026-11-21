"""User folders with client-encrypted names."""

import base64
from collections.abc import Iterator
from typing import Any

import pysequoia
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.folders.models import MailFolder
from tests.openpgp_helpers import encrypt_split, new_device
from tests.unit.fakes import make_app, make_session_factory
from tests.unit.test_messages import Person, compose, person, published, second_device, send

FOLDERS = "/v1/folders"


def encrypted_name(owner: Person, text: str) -> str:
    keys = published(owner.client, owner.user.address)
    certs = [pysequoia.Cert.from_bytes(base64.b64decode(k["material"])) for k in keys]
    pkesks, body = encrypt_split(text.encode(), certs, owner.keys)
    return base64.b64encode(b"".join(pkesks) + body).decode()


def open_name(owner: Person, name: str) -> str:
    result = pysequoia.decrypt(decryptor=owner.keys.tsk.decryptor(), bytes=base64.b64decode(name))
    return bytes(result.bytes or b"").decode()


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


def create(owner: Person, text: str) -> dict[str, Any]:
    response = owner.client.post(FOLDERS, json={"name": encrypted_name(owner, text)})
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


def received(sender: Person, recipient: Person) -> str:
    sent = send(sender, compose(sender, [recipient]))
    assert sent.status_code == 201, sent.text
    return str(sent.json()["id"])


def test_names_are_stored_encrypted_and_open_on_the_owners_device(
    alice: Person, factory: sessionmaker[Session]
) -> None:
    folder = create(alice, "Projects / TEST-ONLY")
    assert open_name(alice, folder["name"]) == "Projects / TEST-ONLY"
    with factory() as session:
        stored = session.scalars(select(MailFolder)).one()
        assert b"TEST-ONLY" not in stored.name
    listed = alice.client.get(FOLDERS).json()["items"]
    assert [(f["id"], f["messages"], f["unread"]) for f in listed] == [(folder["id"], 0, 0)]


def test_plaintext_or_incomplete_names_are_refused(alice: Person) -> None:
    plain = base64.b64encode(b"Projects").decode()
    assert alice.client.post(FOLDERS, json={"name": plain}).status_code == 422
    stranger = new_device()
    pkesks, body = encrypt_split(b"x", [stranger.cert], alice.keys)
    wrong = base64.b64encode(b"".join(pkesks) + body).decode()
    assert alice.client.post(FOLDERS, json={"name": wrong}).status_code == 409
    only_body = base64.b64encode(body).decode()
    assert alice.client.post(FOLDERS, json={"name": only_body}).status_code == 422


def test_move_list_and_delete(alice: Person, bob: Person) -> None:
    message_id = received(bob, alice)
    folder = create(alice, "Receipts")
    moved = alice.client.post(
        f"/v1/messages/{message_id}/move", json={"folder": "custom", "folder_id": folder["id"]}
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["folder_id"] == folder["id"]
    assert alice.client.get("/v1/messages").json()["items"] == []  # left the inbox
    inside = alice.client.get(
        "/v1/messages", params={"folder": "custom", "folder_id": folder["id"]}
    ).json()["items"]
    assert [m["id"] for m in inside] == [message_id]
    assert inside[0]["folder_id"] == folder["id"]
    counts = alice.client.get(FOLDERS).json()["items"][0]
    assert (counts["messages"], counts["unread"]) == (1, 1)

    deleted = alice.client.delete(f"{FOLDERS}/{folder['id']}")
    assert deleted.json() == {"returned": 1}
    inbox = alice.client.get("/v1/messages").json()["items"]
    assert [(m["id"], m["folder"], m["folder_id"]) for m in inbox] == [(message_id, "inbox", None)]


def test_sent_messages_return_to_sent(alice: Person, bob: Person) -> None:
    message_id = received(alice, bob)  # alice is the sender
    folder = create(alice, "Archive")
    alice.client.post(
        f"/v1/messages/{message_id}/move", json={"folder": "custom", "folder_id": folder["id"]}
    )
    alice.client.delete(f"{FOLDERS}/{folder['id']}")
    sent = alice.client.get("/v1/messages", params={"folder": "sent"}).json()["items"]
    assert [m["id"] for m in sent] == [message_id]


def test_move_rules(alice: Person, bob: Person) -> None:
    message_id = received(bob, alice)
    folder = create(alice, "Mine")
    path = f"/v1/messages/{message_id}/move"
    assert alice.client.post(path, json={"folder": "custom"}).status_code == 409
    assert (
        alice.client.post(path, json={"folder": "inbox", "folder_id": folder["id"]}).status_code
        == 409
    )
    # Another account's folder is not found.
    others = create(bob, "Bob's")
    response = alice.client.post(path, json={"folder": "custom", "folder_id": others["id"]})
    assert response.status_code == 404
    assert alice.client.get("/v1/messages", params={"folder": "custom"}).status_code == 409


def test_folders_are_private(alice: Person, bob: Person) -> None:
    folder = create(alice, "Private")
    assert bob.client.get(FOLDERS).json()["items"] == []
    renamed = bob.client.put(f"{FOLDERS}/{folder['id']}", json={"name": encrypted_name(bob, "x")})
    assert renamed.status_code == 404
    assert bob.client.delete(f"{FOLDERS}/{folder['id']}").status_code == 404


def test_new_device_gets_the_names_by_re_encryption(app: Any, alice: Person) -> None:
    folder = create(alice, "Travel")
    phone = second_device(alice, app)
    # The old name has no PKESK for the phone: the laptop re-encrypts it to every key.
    renamed = alice.client.put(
        f"{FOLDERS}/{folder['id']}", json={"name": encrypted_name(alice, "Travel")}
    )
    assert renamed.status_code == 200, renamed.text
    listed = phone.client.get(FOLDERS).json()["items"]
    assert open_name(phone, listed[0]["name"]) == "Travel"
    phone.client.close()


def test_folder_limit(alice: Person, monkeypatch: pytest.MonkeyPatch) -> None:
    from agnusmail.modules.folders import service

    monkeypatch.setattr(service, "MAX_FOLDERS", 2)
    create(alice, "a")
    create(alice, "b")
    response = alice.client.post(FOLDERS, json={"name": encrypted_name(alice, "c")})
    assert response.status_code == 409
