"""Encrypted attachments stored in object storage (protocol v1 §7).

The object is a SEIPDv2 encrypted with its own session key; name, type, session key and
the SHA-256 of the ciphertext travel inside the encrypted message. The server keeps
only size, the client-declared digest, the owner and, once sent, the message that
grants recipients access. Lifecycle: pending → uploaded → attached; unattached ones are
deleted after ``attachment_orphan_hours``.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base


class AttachmentStatus(StrEnum):
    PENDING = "pending"  # upload URL issued
    UPLOADED = "uploaded"  # object present with the declared size
    ATTACHED = "attached"  # referenced by a sent message
    DELETED = "deleted"  # orphan removed (row kept for audit/consistency)


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    object_key: Mapped[str] = mapped_column(String(80), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # SHA-256 of the ciphertext as declared by the uploader; recipients verify it (§7).
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AttachmentStatus.PENDING
    )
    message_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("messages.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("object_key"),
        CheckConstraint(
            "status IN ('pending', 'uploaded', 'attached', 'deleted')", name="status_valid"
        ),
        CheckConstraint("size > 0", name="size_positive"),
        CheckConstraint(
            "(status = 'attached') = (message_id IS NOT NULL)", name="attached_has_message"
        ),
        CheckConstraint(
            "(status = 'deleted') = (deleted_at IS NOT NULL)", name="deleted_timestamp"
        ),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256_hex").ddl_if(
            dialect="postgresql"
        ),
        Index(None, "owner_id", "status"),
        Index(None, "message_id"),
        Index(None, "status", "created_at"),
    )
