"""Stored bytes per account.

``account_usage.stored_bytes`` is a running counter changed in the same transaction as
each write or deletion it accounts for; ``usage.recompute`` (daily worker job) sets it
to the exact value. What counts: the encrypted body of every message the account holds
(once per holder), the attachments it uploaded and its secure-portal messages.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base


class AccountUsage(Base):
    __tablename__ = "account_usage"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    stored_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (CheckConstraint("stored_bytes >= 0", name="stored_bytes_positive"),)
