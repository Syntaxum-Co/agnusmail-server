"""User folders. The name is checked as an envelope, never read."""

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import LimitExceededError, ResourceNotFoundError
from agnusmail.infrastructure.openpgp import (
    TAG_PKESK,
    EnvelopeRejectedError,
    check_seipd_v2,
    packet_tag,
    split_packets,
)
from agnusmail.modules.folders.models import MAX_FOLDERS, MAX_NAME_BYTES, MailFolder
from agnusmail.modules.messages.models import Folder, MailboxEntry, Message
from agnusmail.modules.messages.service import EnvelopeInvalidError, check_owner_pkesks


def check_name(session: Session, owner_id: uuid.UUID, name: bytes, now: datetime) -> None:
    """PKESKs for exactly the owner's published keys (§6.5), then one SEIPDv2: an
    encrypted name every device of the owner can open, and nothing in clear."""
    if len(name) > MAX_NAME_BYTES:
        raise EnvelopeInvalidError(f"name exceeds {MAX_NAME_BYTES} bytes")
    try:
        packets = split_packets(name)
        if len(packets) < 2 or any(packet_tag(p) != TAG_PKESK for p in packets[:-1]):
            raise EnvelopeRejectedError("not_pkesks_then_seipd")
        check_seipd_v2(packets[-1])
    except EnvelopeRejectedError as exc:
        raise EnvelopeInvalidError(f"name: {exc.reason}") from exc
    check_owner_pkesks(session, owner_id, packets[:-1], now)


def own_folder(session: Session, owner_id: uuid.UUID, folder_id: uuid.UUID) -> MailFolder:
    folder = session.get(MailFolder, folder_id)
    if folder is None or folder.user_id != owner_id:
        raise ResourceNotFoundError()
    return folder


def create(session: Session, owner_id: uuid.UUID, name: bytes, now: datetime) -> MailFolder:
    check_name(session, owner_id, name, now)
    count = session.scalar(
        select(func.count()).select_from(MailFolder).where(MailFolder.user_id == owner_id)
    )
    if (count or 0) >= MAX_FOLDERS:
        raise LimitExceededError(f"at most {MAX_FOLDERS} folders")
    folder = MailFolder(user_id=owner_id, name=name, created_at=now, updated_at=now)
    session.add(folder)
    session.flush()
    return folder


def rename(
    session: Session, owner_id: uuid.UUID, folder_id: uuid.UUID, name: bytes, now: datetime
) -> MailFolder:
    """Also how a new device gets the names: another device re-encrypts them."""
    folder = own_folder(session, owner_id, folder_id)
    check_name(session, owner_id, name, now)
    folder.name = name
    folder.updated_at = now
    session.flush()
    return folder


def delete(session: Session, owner_id: uuid.UUID, folder_id: uuid.UUID) -> int:
    """Remove the folder; its messages go back to their origin (inbox or sent)."""
    folder = own_folder(session, owner_id, folder_id)
    entries = session.execute(
        select(MailboxEntry, Message.sender_id)
        .join(Message, Message.id == MailboxEntry.message_id)
        .where(MailboxEntry.folder_id == folder.id)
    ).all()
    for entry, sender_id in entries:
        entry.folder = Folder.SENT if sender_id == owner_id else Folder.INBOX
        entry.folder_id = None
    session.flush()
    session.delete(folder)
    session.flush()
    return len(entries)


def list_folders(session: Session, owner_id: uuid.UUID) -> list[tuple[MailFolder, int, int]]:
    """Each folder with its message count and unread count."""
    counts = dict(
        (row[0], (row[1], row[2]))
        for row in session.execute(
            select(
                MailboxEntry.folder_id,
                func.count(),
                func.count().filter(MailboxEntry.read_at.is_(None)),
            )
            .where(MailboxEntry.user_id == owner_id, MailboxEntry.folder_id.is_not(None))
            .group_by(MailboxEntry.folder_id)
        ).all()
    )
    folders = session.scalars(
        select(MailFolder)
        .where(MailFolder.user_id == owner_id)
        .order_by(MailFolder.created_at, MailFolder.id)
    )
    return [(f, *counts.get(f.id, (0, 0))) for f in folders]
