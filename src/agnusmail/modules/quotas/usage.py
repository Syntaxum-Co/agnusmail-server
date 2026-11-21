"""Storage accounting."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from agnusmail.modules.quotas.models import AccountUsage


def add_usage(session: Session, user_id: uuid.UUID, delta: int) -> None:
    """Add ``delta`` bytes (negative to release), in the caller's transaction. Never
    below zero: a release after a recomputation must not fail the deletion."""
    if delta == 0:
        return
    now = datetime.now(UTC)
    dialect = session.get_bind().dialect.name
    insert: Any = (
        pg_insert(AccountUsage) if dialect == "postgresql" else sqlite_insert(AccountUsage)
    )
    statement = insert.values(user_id=user_id, stored_bytes=max(delta, 0), updated_at=now)
    session.execute(
        statement.on_conflict_do_update(
            index_elements=["user_id"],
            set_={
                "stored_bytes": func.greatest(AccountUsage.stored_bytes + delta, 0)
                if dialect == "postgresql"
                else func.max(AccountUsage.stored_bytes + delta, 0),
                "updated_at": now,
            },
        )
    )


def lock_usage(session: Session, user_id: uuid.UUID) -> None:
    """Lock the account's usage row (created if missing) until the transaction ends:
    quota checks and the writes they allow happen one account-writer at a time."""
    dialect = session.get_bind().dialect.name
    insert: Any = (
        pg_insert(AccountUsage) if dialect == "postgresql" else sqlite_insert(AccountUsage)
    )
    session.execute(
        insert.values(
            user_id=user_id, stored_bytes=0, updated_at=datetime.now(UTC)
        ).on_conflict_do_nothing(index_elements=["user_id"])
    )
    session.execute(
        select(AccountUsage.user_id).where(AccountUsage.user_id == user_id).with_for_update()
    )


def stored_bytes(session: Session, user_id: uuid.UUID) -> int:
    value = session.scalar(select(AccountUsage.stored_bytes).where(AccountUsage.user_id == user_id))
    return int(value or 0)


def exact_usage(session: Session, user_id: uuid.UUID) -> int:
    """What the counter should be, computed from the stored data."""
    from agnusmail.modules.attachments.models import Attachment, AttachmentStatus
    from agnusmail.modules.messages.models import MailboxEntry, Message
    from agnusmail.modules.portal.models import PortalMessage

    messages = session.scalar(
        select(func.coalesce(func.sum(Message.size), 0))
        .select_from(MailboxEntry)
        .join(Message, Message.id == MailboxEntry.message_id)
        .where(MailboxEntry.user_id == user_id)
    )
    attachments = session.scalar(
        select(func.coalesce(func.sum(Attachment.size), 0)).where(
            Attachment.owner_id == user_id,
            Attachment.status.in_([AttachmentStatus.UPLOADED, AttachmentStatus.ATTACHED]),
        )
    )
    portal = session.scalar(
        select(func.coalesce(func.sum(PortalMessage.size), 0)).where(
            PortalMessage.sender_id == user_id
        )
    )
    return int(messages or 0) + int(attachments or 0) + int(portal or 0)


def recompute(session: Session, user_id: uuid.UUID) -> int:
    """Set the counter to the exact value; returns the correction applied."""
    exact = exact_usage(session, user_id)
    current = session.get(AccountUsage, user_id, with_for_update=True)
    if current is None:
        session.add(AccountUsage(user_id=user_id, stored_bytes=exact))
        session.flush()
        return exact
    correction = exact - current.stored_bytes
    if correction:
        current.stored_bytes = exact
        current.updated_at = datetime.now(UTC)
        session.flush()
    return correction
