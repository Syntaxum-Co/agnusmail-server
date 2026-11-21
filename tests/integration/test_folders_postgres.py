"""User folders on PostgreSQL: the database keeps entries and folders
consistent even if the application did not."""

import secrets
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.folders.models import MailFolder
from agnusmail.modules.identity.models import User
from agnusmail.modules.messages.models import MailboxEntry, Message

pytestmark = pytest.mark.integration


@pytest.fixture
def engine() -> Iterator[Engine]:
    db_engine = create_db_engine(Settings(_env_file=None))  # type: ignore[call-arg]
    try:
        yield db_engine
    finally:
        db_engine.dispose()


def test_database_rules(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        folder = MailFolder(user_id=user.id, name=b"\x01")
        message = Message(
            sender_id=user.id, client_message_id=secrets.token_hex(16), body=b"x", size=1
        )
        session.add_all([folder, message])
        session.flush()
        entry = MailboxEntry(
            message_id=message.id, user_id=user.id, folder="custom", folder_id=folder.id
        )
        session.add(entry)
        session.flush()  # assigns entry.id
        ids = (user.id, folder.id, entry.id)
    user_id, folder_id, entry_id = ids

    bad_updates = [
        "UPDATE mailbox_entries SET folder_id = NULL WHERE id = :e",  # custom without folder
        "UPDATE mailbox_entries SET folder = 'inbox' WHERE id = :e",  # folder_id outside custom
        "DELETE FROM mail_folders WHERE id = :f",  # a folder still holding messages
    ]
    for statement in bad_updates:
        with engine.connect() as connection, pytest.raises(IntegrityError):
            connection.execute(text(statement), {"e": entry_id, "f": folder_id})
    with Session(engine) as session:
        assert session.scalar(select(MailFolder.id).where(MailFolder.user_id == user_id))
