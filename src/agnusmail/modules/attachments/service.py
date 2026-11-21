"""Attachment use cases. Synchronous; run inside ``run_in_transaction``.

Access rule: the uploader always; once attached, every participant of the message
(anyone with a mailbox entry for it). Everyone else gets 404, like any foreign resource.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.exceptions import (
    AgnusmailError,
    InvalidStateError,
    LimitExceededError,
    ResourceNotFoundError,
)
from agnusmail.core.logging import get_logger
from agnusmail.infrastructure.object_storage import ObjectStorage
from agnusmail.modules.attachments.models import Attachment, AttachmentStatus
from agnusmail.modules.messages.models import MailboxEntry
from agnusmail.modules.quotas.usage import add_usage

log = get_logger(__name__)

MAX_PENDING_PER_USER = 50

if TYPE_CHECKING:
    from agnusmail.modules.quotas.policy import QuotaPolicy


class AttachmentsUnavailableError(AgnusmailError):
    status_code = 503
    message = "attachments are not configured"
    code = "ATTACHMENTS_UNAVAILABLE"


class AttachmentRejectedError(AgnusmailError):
    status_code = 422
    message = "attachment rejected"
    code = "ATTACHMENT_REJECTED"


@dataclass(frozen=True)
class AttachmentLimits:
    max_bytes: int
    max_per_message: int


def create_upload(
    session: Session,
    owner_id: uuid.UUID,
    size: int,
    sha256: str,
    limits: AttachmentLimits,
    quota: "QuotaPolicy | None" = None,
) -> Attachment:
    if size > limits.max_bytes:
        raise AttachmentRejectedError(f"attachment exceeds {limits.max_bytes} bytes")
    if quota is not None:  # checked when the upload is declared
        quota.require_space(session, owner_id, size, datetime.now(UTC))
    pending = session.scalar(
        select(func.count())
        .select_from(Attachment)
        .where(Attachment.owner_id == owner_id, Attachment.status == AttachmentStatus.PENDING)
    )
    if int(pending or 0) >= MAX_PENDING_PER_USER:
        raise LimitExceededError("too many uploads in progress")
    attachment_id = uuid.uuid4()
    attachment = Attachment(
        id=attachment_id,
        owner_id=owner_id,
        object_key=f"att/{attachment_id}",
        size=size,
        sha256=sha256,
        status=AttachmentStatus.PENDING,
    )
    session.add(attachment)
    session.flush()
    return attachment


def _owned(session: Session, owner_id: uuid.UUID, attachment_id: uuid.UUID) -> Attachment:
    attachment = session.scalars(
        select(Attachment)
        .where(Attachment.id == attachment_id, Attachment.owner_id == owner_id)
        .with_for_update()
    ).one_or_none()
    if attachment is None or attachment.status == AttachmentStatus.DELETED:
        raise ResourceNotFoundError("attachment not found")
    return attachment


def complete_upload(
    session: Session,
    owner_id: uuid.UUID,
    attachment_id: uuid.UUID,
    storage: ObjectStorage,
    now: datetime,
) -> Attachment:
    """Confirm the upload: the object exists with exactly the declared size."""
    attachment = _owned(session, owner_id, attachment_id)
    if attachment.status != AttachmentStatus.PENDING:
        raise InvalidStateError(f"attachment is {attachment.status}")
    size = storage.object_size(attachment.object_key)
    if size is None:
        raise InvalidStateError("the object has not been uploaded")
    if size != attachment.size:
        storage.delete(attachment.object_key)  # the orphan cleanup removes the row later
        raise AttachmentRejectedError("uploaded size differs from the declared size")
    attachment.status = AttachmentStatus.UPLOADED
    attachment.uploaded_at = now
    add_usage(session, owner_id, attachment.size)
    session.flush()
    return attachment


def attach_to_message(
    session: Session,
    sender_id: uuid.UUID,
    message_id: uuid.UUID,
    attachment_ids: list[uuid.UUID],
    limits: AttachmentLimits,
) -> None:
    """Called inside the message transaction: grants the participants access."""
    if len(attachment_ids) > limits.max_per_message:
        raise AttachmentRejectedError(f"at most {limits.max_per_message} attachments")
    if len(set(attachment_ids)) != len(attachment_ids):
        raise AttachmentRejectedError("duplicate attachment")
    for attachment_id in attachment_ids:
        attachment = _owned(session, sender_id, attachment_id)
        if attachment.status != AttachmentStatus.UPLOADED:
            raise InvalidStateError(f"attachment {attachment_id} is {attachment.status}")
        attachment.status = AttachmentStatus.ATTACHED
        attachment.message_id = message_id
    session.flush()


def readable(session: Session, user_id: uuid.UUID, attachment_id: uuid.UUID) -> Attachment:
    attachment = session.get(Attachment, attachment_id)
    if attachment is None or attachment.status in (
        AttachmentStatus.DELETED,
        AttachmentStatus.PENDING,
    ):
        raise ResourceNotFoundError("attachment not found")
    if attachment.owner_id == user_id:
        return attachment
    if attachment.message_id is not None:
        participant = session.scalar(
            select(MailboxEntry.id).where(
                MailboxEntry.message_id == attachment.message_id,
                MailboxEntry.user_id == user_id,
            )
        )
        if participant is not None:
            return attachment
    raise ResourceNotFoundError("attachment not found")


def cleanup_orphans(
    factory: sessionmaker[Session], storage: ObjectStorage, *, older_than_hours: int
) -> int:
    """Delete uploads never attached to a message (worker job). Idempotent."""
    cutoff = datetime.now(UTC) - timedelta(hours=older_than_hours)
    removed = 0
    with factory() as session, session.begin():
        orphans = session.scalars(
            select(Attachment)
            .where(
                Attachment.status.in_([AttachmentStatus.PENDING, AttachmentStatus.UPLOADED]),
                Attachment.created_at < cutoff,
            )
            .with_for_update(skip_locked=True)
        ).all()
        for attachment in orphans:
            storage.delete(attachment.object_key)  # deleting a missing object is a no-op
            if attachment.status == AttachmentStatus.UPLOADED:  # counted since completed
                add_usage(session, attachment.owner_id, -attachment.size)
            attachment.status = AttachmentStatus.DELETED
            attachment.deleted_at = datetime.now(UTC)
            removed += 1
    return removed
