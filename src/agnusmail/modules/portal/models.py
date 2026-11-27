"""Secure portal (protocol v1 §11).

E2EE with a shared secret: the sender encrypts with a client-generated password (SKESK
v6, Argon2) and to their own keys (PKESKs); the external recipient's browser decrypts
with the password. The server stores only the OpenPGP message.

- ``portal_messages``: the envelope (PKESKs + SKESK + SEIPDv2), deleted at expiry
  (at most 30 days) or when the sender deletes it.
- ``portal_links``: one per recipient. Only the SHA-256 of the link token is stored, so
  the database alone does not open the portal; the token is shown once, at creation.

View once (``view_seconds`` set): the first access of a link starts its window
(``viewable_until``); after it the link answers 404, and once every link has been opened
the message expires when the last window ends, so the purge deletes it.
"""

import uuid
from datetime import UTC, datetime

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
from agnusmail.modules.outbound.models import MAX_ADDRESS_LENGTH

MAX_PORTAL_DAYS = 30  # spec §11
MIN_VIEW_SECONDS = 60
MAX_VIEW_SECONDS = 3600


class PortalMessage(Base):
    __tablename__ = "portal_messages"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    sender_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    client_message_id: Mapped[str] = mapped_column(String(32), nullable=False)
    envelope: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # View once: how long a link stays readable after its first access; null = until expiry.
    view_seconds: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("sender_id", "client_message_id"),
        CheckConstraint(
            "view_seconds IS NULL OR "
            f"view_seconds BETWEEN {MIN_VIEW_SECONDS} AND {MAX_VIEW_SECONDS}",
            name="view_seconds_range",
        ),
        CheckConstraint("size = length(envelope) AND size > 0", name="size_matches_envelope"),
        CheckConstraint("expires_at <= created_at + interval '30 days'", name="ttl_30_days").ddl_if(
            dialect="postgresql"
        ),
        CheckConstraint(
            "client_message_id ~ '^[0-9a-f]{32}$'", name="client_message_id_hex"
        ).ddl_if(dialect="postgresql"),
        Index(None, "sender_id", "created_at"),
        Index(None, "expires_at"),
    )


class PortalLink(Base):
    __tablename__ = "portal_links"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    portal_message_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("portal_messages.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient: Mapped[str] = mapped_column(String(MAX_ADDRESS_LENGTH), nullable=False)
    replies: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_access_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # View once: set by the first access; the link answers 404 from then on.
    viewable_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("token_hash"),
        UniqueConstraint("portal_message_id", "recipient"),
        CheckConstraint("replies BETWEEN 0 AND 100", name="replies_range"),
        CheckConstraint("token_hash ~ '^[0-9a-f]{64}$'", name="token_hash_hex").ddl_if(
            dialect="postgresql"
        ),
    )
