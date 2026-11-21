"""Storage accounting and permanent deletion.

After every operation the running counter must equal what is really stored
(``exact_usage``), and deleting from the trash must release it without losing anyone
else's copy.
"""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.attachments.models import Attachment
from agnusmail.modules.messages.models import Message, MessageKey
from agnusmail.modules.quotas.models import AccountUsage
from agnusmail.modules.quotas.usage import exact_usage, recompute, stored_bytes
from tests.unit.fakes import FakeObjectStorage, make_app, make_session_factory
from tests.unit.test_attachments import complete, send_with, upload
from tests.unit.test_messages import MESSAGES, Person, compose, person, send


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return make_app(session_factory=factory)[0]


@pytest.fixture
def pair(app: Any) -> Iterator[tuple[Person, Person]]:
    alice, bob = person(app), person(app)
    yield alice, bob
    alice.client.close()
    bob.client.close()


def usage(factory: sessionmaker[Session], who: Person) -> tuple[int, int]:
    """(counter, exact) for an account: they must always agree."""
    owner = uuid.UUID(who.user.user_id)
    with factory() as session:
        return stored_bytes(session, owner), exact_usage(session, owner)


def trash_and_delete(who: Person, message_id: str) -> Any:
    who.client.post(f"{MESSAGES}/{message_id}/move", json={"folder": "trash"})
    return who.client.delete(f"{MESSAGES}/{message_id}")


def test_messages_count_for_every_holder(
    pair: tuple[Person, Person], factory: sessionmaker[Session]
) -> None:
    alice, bob = pair
    sent = send(alice, compose(alice, [bob])).json()
    for who in (alice, bob):
        counter, exact = usage(factory, who)
        assert counter == exact == sent["size"]


def test_delete_from_trash_releases_and_keeps_others_copy(
    pair: tuple[Person, Person], factory: sessionmaker[Session]
) -> None:
    alice, bob = pair
    message_id = send(alice, compose(alice, [bob])).json()["id"]
    assert bob.client.delete(f"{MESSAGES}/{message_id}").status_code == 409  # not in trash
    assert trash_and_delete(bob, message_id).status_code == 204
    assert usage(factory, bob) == (0, 0)
    assert bob.client.get(f"{MESSAGES}/{message_id}").status_code == 404
    # Alice still has it, with her keys.
    assert alice.client.get(f"{MESSAGES}/{message_id}").json()["pkesks"]
    with factory() as session:
        holders = session.scalars(
            select(MessageKey.user_id).where(MessageKey.message_id == uuid.UUID(message_id))
        ).all()
        assert {str(h) for h in holders} == {alice.user.user_id}
    assert trash_and_delete(alice, message_id).status_code == 204
    with factory() as session:
        assert session.get(Message, uuid.UUID(message_id)) is None
    assert usage(factory, alice) == (0, 0)


def test_others_cannot_delete(pair: tuple[Person, Person], app: Any) -> None:
    alice, bob = pair
    message_id = send(alice, compose(alice, [bob])).json()["id"]
    carol = person(app)
    assert carol.client.delete(f"{MESSAGES}/{message_id}").status_code == 404
    carol.client.close()


def test_attachments_count_for_the_uploader_and_go_with_the_message(
    app: Any, pair: tuple[Person, Person], factory: sessionmaker[Session]
) -> None:
    alice, bob = pair
    storage: FakeObjectStorage = app.state.object_storage
    data = b"\x01" * 3000
    attachment_id = upload(alice, storage, data)
    assert usage(factory, alice) == (0, 0)  # not counted before the upload is confirmed
    assert complete(alice, attachment_id).status_code == 200
    assert usage(factory, alice) == (3000, 3000)
    message_id = send_with(alice, bob, [attachment_id]).json()["id"]
    trash_and_delete(alice, message_id)
    assert storage.objects  # bob still holds the message: the attachment stays
    trash_and_delete(bob, message_id)
    assert storage.objects == {}
    with factory() as session:
        assert session.get(Attachment, uuid.UUID(attachment_id)).status == "deleted"  # type: ignore[union-attr]
    assert usage(factory, alice) == (0, 0)
    assert usage(factory, bob) == (0, 0)


def test_recompute_corrects_drift(
    pair: tuple[Person, Person], factory: sessionmaker[Session]
) -> None:
    alice, bob = pair
    size = send(alice, compose(alice, [bob])).json()["size"]
    owner = uuid.UUID(alice.user.user_id)
    with factory() as session, session.begin():
        row = session.get(AccountUsage, owner)
        assert row is not None
        row.stored_bytes = 7
    with factory() as session, session.begin():
        assert recompute(session, owner) == size - 7
    assert usage(factory, alice) == (size, size)
    with factory() as session, session.begin():
        assert recompute(session, owner) == 0
