"""Outbound conventional SMTP queue (protocol v1 §10).

NOT end-to-end encrypted: the recipient's provider receives the message in clear. Until
delivery, the message waits here encrypted by the client to the outbound service's key
(``outbound_keys``); only that service can decrypt it.

- ``outbound_keys``: public certificates of the queue keys (device profile §3.1), kept
  after rotation. Published at ``/v1/outbound/keys``.
- ``outbound_messages``: one queued message. ``payload`` (PKESK || SEIPDv2) exists only
  while the message is ``queued``; it is erased on completion and at the latest 72 h
  after submission (``expires_at``).
- ``outbound_recipients``: envelope recipients and their delivery state. Only SMTP reply
  codes are kept, never the server's text.
"""

import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

QUEUE_LIMIT = timedelta(hours=72)  # nothing stays longer (also a CHECK in the DB)
# The worker's fallback purge runs this often (``outbound.purge``), so expiring a bit
# earlier keeps the 72 h limit even when only the worker is running.
PURGE_INTERVAL = timedelta(minutes=10)
QUEUE_TTL = QUEUE_LIMIT - PURGE_INTERVAL
MAX_ADDRESS_LENGTH = 254  # RFC 5321 §4.5.3.1.3 path limit minus the brackets


class OutboundStatus(StrEnum):
    QUEUED = "queued"  # payload present, deliveries pending
    DONE = "done"  # every recipient delivered or failed for good
    EXPIRED = "expired"  # 72 h passed with recipients still pending


class OutboundKind(StrEnum):
    MESSAGE = "message"  # written by the user
    PORTAL_NOTICE = "portal_notice"  # server-generated notice of a portal message (§11)


class RecipientStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"


class OutboundKey(Base):
    __tablename__ = "outbound_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    material: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("fingerprint"),
        UniqueConstraint("encryption_fingerprint"),
        CheckConstraint("length(material) BETWEEN 1 AND 16384", name="material_length"),
        CheckConstraint("fingerprint ~ '^[0-9a-f]{64}$'", name="fingerprint_hex").ddl_if(
            dialect="postgresql"
        ),
        CheckConstraint(
            "encryption_fingerprint ~ '^[0-9a-f]{64}$'", name="encryption_fingerprint_hex"
        ).ddl_if(dialect="postgresql"),
    )


class OutboundMessage(Base):
    __tablename__ = "outbound_messages"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    client_message_id: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # The user's address at submission: the only From and MAIL FROM allowed.
    sender_address: Mapped[str] = mapped_column(String(MAX_ADDRESS_LENGTH), nullable=False)
    key_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)  # encryption subkey
    payload: Mapped[bytes | None] = mapped_column(LargeBinary)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("user_id", "client_message_id"),
        CheckConstraint("status IN ('queued', 'done', 'expired')", name="status_valid"),
        CheckConstraint("kind IN ('message', 'portal_notice')", name="kind_valid"),
        # Ciphertext exists only while queued; finished rows never keep it.
        CheckConstraint("(status = 'queued') = (payload IS NOT NULL)", name="payload_only_queued"),
        CheckConstraint("(status = 'queued') = (finished_at IS NULL)", name="finished_state"),
        CheckConstraint("payload IS NULL OR length(payload) = size", name="size_matches_payload"),
        CheckConstraint("size > 0", name="size_positive"),
        CheckConstraint("expires_at <= created_at + interval '72 hours'", name="ttl_72h").ddl_if(
            dialect="postgresql"
        ),
        CheckConstraint(
            "client_message_id ~ '^[0-9a-f]{32}$'", name="client_message_id_hex"
        ).ddl_if(dialect="postgresql"),
        Index(None, "status", "next_attempt_at"),
        Index(None, "user_id", "created_at"),
    )


class OutboundRecipient(Base):
    __tablename__ = "outbound_recipients"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    outbound_message_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("outbound_messages.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str] = mapped_column(String(MAX_ADDRESS_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    smtp_code: Mapped[int | None] = mapped_column(Integer)
    # Enhanced status code (RFC 3463, e.g. "5.1.1") or a stable local reason.
    smtp_status: Mapped[str | None] = mapped_column(String(32))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("outbound_message_id", "address"),
        CheckConstraint(
            "status IN ('pending', 'delivered', 'failed')", name="recipient_status_valid"
        ),
        CheckConstraint("smtp_code IS NULL OR smtp_code BETWEEN 200 AND 599", name="smtp_code"),
    )
