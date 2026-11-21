"""User folders.

The name is an OpenPGP message (PKESKs for every published key of the owner + SEIPDv2)
that only the owner's devices open: the server sees how many folders exist and which
messages are in each, never their names. Messages in a folder have
``mailbox_entries.folder = 'custom'`` and ``folder_id`` set.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, LargeBinary, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

MAX_FOLDERS = 100
MAX_NAME_BYTES = 4096


class MailFolder(Base):
    __tablename__ = "mail_folders"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # encrypted envelope
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        CheckConstraint(f"length(name) BETWEEN 1 AND {MAX_NAME_BYTES}", name="name_length"),
        Index(None, "user_id", "created_at"),
    )
