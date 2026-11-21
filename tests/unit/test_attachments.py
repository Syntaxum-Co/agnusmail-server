"""Encrypted attachments (protocol v1 §7) with an in-memory S3 stand-in."""

import hashlib
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.attachments.models import Attachment, AttachmentStatus
from agnusmail.modules.attachments.service import cleanup_orphans
from agnusmail.testing.fakes import FakeObjectStorage, make_app, make_session_factory, make_settings
from agnusmail.testing.people import Person, compose, person

ATTACHMENTS = "/v1/attachments"


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return make_app(session_factory=factory)[0]


@pytest.fixture
def storage(app: Any) -> FakeObjectStorage:
    return app.state.object_storage  # type: ignore[no-any-return]


@pytest.fixture
def people(app: Any) -> Iterator[tuple[Person, Person, Person]]:
    alice, bob, carol = person(app), person(app), person(app)
    yield alice, bob, carol
    for p in (alice, bob, carol):
        p.client.close()


def upload(
    owner: Person, storage: FakeObjectStorage, data: bytes, *, declared: int | None = None
) -> str:
    """Client flow: declare, upload the ciphertext with the URL, confirm."""
    created = owner.client.post(
        ATTACHMENTS,
        json={"size": declared or len(data), "sha256": hashlib.sha256(data).hexdigest()},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    storage.upload(body["upload_url"], data)
    return str(body["id"])


def complete(owner: Person, attachment_id: str) -> Any:
    return owner.client.post(f"{ATTACHMENTS}/{attachment_id}/complete")


def send_with(sender: Person, to: Person, attachment_ids: list[str]) -> Any:
    payload = compose(sender, [to]) | {"attachments": attachment_ids}
    return sender.client.post("/v1/messages", json=payload)


def test_attachment_round_trip(
    people: tuple[Person, Person, Person], storage: FakeObjectStorage
) -> None:
    alice, bob, carol = people
    ciphertext = secrets.token_bytes(5000)  # opaque to the server (SEIPDv2 in real clients)
    attachment_id = upload(alice, storage, ciphertext)
    confirmed = complete(alice, attachment_id)
    assert confirmed.status_code == 200 and confirmed.json()["status"] == "uploaded"
    assert bob.client.get(f"{ATTACHMENTS}/{attachment_id}").status_code == 404  # not shared yet

    assert send_with(alice, bob, [attachment_id]).status_code == 201
    download = bob.client.get(f"{ATTACHMENTS}/{attachment_id}")
    assert download.status_code == 200
    body = download.json()
    assert body["status"] == "attached" and body["size"] == 5000
    assert body["sha256"] == hashlib.sha256(ciphertext).hexdigest()  # recipients verify it
    assert body["download_url"].startswith("https://storage.test/get/att/")
    assert body["expires_in"] == 60
    assert alice.client.get(f"{ATTACHMENTS}/{attachment_id}").status_code == 200  # owner
    assert carol.client.get(f"{ATTACHMENTS}/{attachment_id}").status_code == 404  # stranger


def test_upload_must_match_the_declared_size(
    people: tuple[Person, Person, Person], storage: FakeObjectStorage
) -> None:
    alice, _, _ = people
    attachment_id = upload(alice, storage, b"x" * 100, declared=200)
    response = complete(alice, attachment_id)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ATTACHMENT_REJECTED"
    assert storage.object_size(f"att/{attachment_id}") is None  # removed

    created = alice.client.post(ATTACHMENTS, json={"size": 10, "sha256": "0" * 64}).json()
    assert complete(alice, created["id"]).status_code == 409  # nothing uploaded yet


def test_attaching_follows_ownership_and_state(
    people: tuple[Person, Person, Person], storage: FakeObjectStorage
) -> None:
    alice, bob, carol = people
    mine = upload(alice, storage, b"a" * 50)
    complete(alice, mine)
    pending = upload(alice, storage, b"b" * 50)  # never completed
    theirs = upload(carol, storage, b"c" * 50)
    complete(carol, theirs)

    assert send_with(alice, bob, [theirs]).status_code == 404  # not hers
    assert send_with(alice, bob, [pending]).status_code == 409  # not uploaded
    assert send_with(alice, bob, [mine, mine]).status_code == 422  # duplicate
    assert send_with(alice, bob, [mine]).status_code == 201
    assert send_with(alice, bob, [mine]).status_code == 409  # already attached


def test_failed_send_leaves_the_attachment_unattached(
    people: tuple[Person, Person, Person], storage: FakeObjectStorage
) -> None:
    alice, bob, _ = people
    attachment_id = upload(alice, storage, b"z" * 40)
    complete(alice, attachment_id)
    payload = compose(alice, [bob]) | {"attachments": [attachment_id]}
    payload["recipients"][0]["pkesks"] = payload["self_pkesks"]  # incomplete: 409
    assert alice.client.post("/v1/messages", json=payload).status_code == 409
    assert alice.client.get(f"{ATTACHMENTS}/{attachment_id}").json()["status"] == "uploaded"


def test_limits_and_validation() -> None:
    app, _ = make_app(make_settings(max_attachment_bytes=2048, max_attachments_per_message=1))
    alice, bob = person(app), person(app)
    storage: FakeObjectStorage = app.state.object_storage
    try:
        too_big = alice.client.post(ATTACHMENTS, json={"size": 4096, "sha256": "0" * 64})
        assert too_big.status_code == 422
        for bad in ({"size": 0, "sha256": "0" * 64}, {"size": 10, "sha256": "XYZ"}, {"size": 10}):
            assert alice.client.post(ATTACHMENTS, json=bad).status_code == 422
        first, second = upload(alice, storage, b"1" * 10), upload(alice, storage, b"2" * 10)
        complete(alice, first)
        complete(alice, second)
        assert send_with(alice, bob, [first, second]).status_code == 422  # max 1
    finally:
        alice.client.close()
        bob.client.close()


def test_attachments_unavailable_without_storage() -> None:
    app, _ = make_app(object_storage=None)  # no endpoint configured
    alice = person(app)
    try:
        response = alice.client.post(ATTACHMENTS, json={"size": 10, "sha256": "0" * 64})
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "ATTACHMENTS_UNAVAILABLE"
    finally:
        alice.client.close()


def test_orphans_are_cleaned_up(
    people: tuple[Person, Person, Person],
    storage: FakeObjectStorage,
    factory: sessionmaker[Session],
) -> None:
    alice, bob, _ = people
    orphan = upload(alice, storage, b"o" * 30)
    complete(alice, orphan)
    kept = upload(alice, storage, b"k" * 30)
    complete(alice, kept)
    send_with(alice, bob, [kept])
    with factory() as session, session.begin():
        for row in session.query(Attachment).all():
            row.created_at = datetime.now(UTC) - timedelta(hours=48)

    assert cleanup_orphans(factory, storage, older_than_hours=24) == 1
    assert storage.deleted == [f"att/{orphan}"]
    with factory() as session:
        statuses = {str(a.id): a.status for a in session.query(Attachment).all()}
    assert statuses == {orphan: AttachmentStatus.DELETED, kept: AttachmentStatus.ATTACHED}
    assert alice.client.get(f"{ATTACHMENTS}/{orphan}").status_code == 404
    assert cleanup_orphans(factory, storage, older_than_hours=24) == 0  # idempotent


def test_storage_settings_must_be_complete() -> None:
    with pytest.raises(ValidationError, match="object storage"):
        make_settings(object_storage_endpoint="http://s3.local")
    complete_settings = make_settings(
        object_storage_endpoint="http://s3.local",
        object_storage_bucket="b",
        object_storage_access_key="k",
        object_storage_secret_key="s",
    )
    assert "s" not in repr(complete_settings.object_storage_secret_key)  # SecretStr
