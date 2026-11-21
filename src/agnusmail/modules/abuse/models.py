"""Abuse reports and account restrictions. Metadata only."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base


class ReportCategory(StrEnum):
    SPAM = "spam"
    PHISHING = "phishing"
    HARASSMENT = "harassment"
    MALWARE = "malware"
    OTHER = "other"


class RestrictionReason(StrEnum):
    REPORTS = "reports"
    BOUNCES = "bounces"


class AbuseReport(Base):
    """A recipient says a message was abusive. No content: which message, which kind."""

    __tablename__ = "abuse_reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Not a foreign key: the report outlives the message if everyone deletes it.
    message_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    reporter_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    reported_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("message_id", "reporter_id"),
        CheckConstraint(
            "category IN ('spam', 'phishing', 'harassment', 'malware', 'other')",
            name="category_valid",
        ),
        CheckConstraint("reporter_id <> reported_id", name="not_self"),
        Index(None, "reported_id", "created_at"),
    )


class AccountRestriction(Base):
    __tablename__ = "account_restrictions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    reason: Mapped[str] = mapped_column(String(16), nullable=False)
    restricted_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (CheckConstraint("reason IN ('reports', 'bounces')", name="reason_valid"),)
