"""E2EE messages between Agnusmail users (protocol v1 §6).

- ``messages``: one row per message with the SEIPDv2 body (ciphertext only) stored once.
- ``message_keys``: one v6 PKESK per (message, device key) — the session key encrypted
  to that device. A device's OpenPGP message is ``PKESK(device) || body``.
- ``mailbox_entries``: each participant's view (folder, read state): fixed
  folders (``inbox``, ``sent``, ``trash``) and user folders
  (``custom`` + ``folder_id``, names encrypted on the client).

What the server sees is limited to routing metadata (spec §1): sender, recipients,
devices (PKESK fingerprints), time and size. No subject, body or MIME in clear.

``origin``: ``internal`` (E2EE from an Agnusmail sender); ``external`` (received by the
SMTP gateway and encrypted on arrival, spec §9 — no sender account, and the external
sender's address is not stored outside the ciphertext); ``outbound`` (the sender's own
E2EE copy of a message sent through the conventional, NOT end-to-end encrypted, outbound
channel, spec §10 — only in the sender's Sent folder); ``portal`` (a reply written in the
secure portal by an external recipient, spec §11 — no sender account).
"""

import uuid
from datetime import UTC, datetime
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

CLIENT_MESSAGE_ID_LENGTH = 32  # 128 random bits, lowercase hex (spec §2)


class MessageOrigin(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    OUTBOUND = "outbound"
    PORTAL = "portal"


# Origins with an Agnusmail sender account.
ORIGINS_WITH_SENDER = (MessageOrigin.INTERNAL, MessageOrigin.OUTBOUND)


class Folder(StrEnum):
    INBOX = "inbox"
    SENT = "sent"
    TRASH = "trash"
    CUSTOM = "custom"  # a user folder: ``folder_id`` says which


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    sender_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT")
    )
    origin: Mapped[str] = mapped_column(String(16), nullable=False, default=MessageOrigin.INTERNAL)
    # Client-chosen id, bound inside the signed MIME (Message-ID); unique per sender
    # (idempotency and replay protection on submission, spec §6.5/§6.6). Random, chosen
    # by the gateway, for external messages.
    client_message_id: Mapped[str] = mapped_column(String(CLIENT_MESSAGE_ID_LENGTH), nullable=False)
    body: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # SEIPDv2 packet
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("sender_id", "client_message_id"),
        CheckConstraint("size = length(body) AND size > 0", name="size_matches_body"),
        CheckConstraint(
            "origin IN ('internal', 'external', 'outbound', 'portal')", name="origin_valid"
        ),
        CheckConstraint(
            "(origin IN ('internal', 'outbound')) = (sender_id IS NOT NULL)", name="origin_sender"
        ),
        CheckConstraint("length(client_message_id) = 32", name="client_message_id_length"),
        CheckConstraint(
            "client_message_id ~ '^[0-9a-f]{32}$'", name="client_message_id_hex"
        ).ddl_if(dialect="postgresql"),
    )


class MessageKey(Base):
    __tablename__ = "message_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    message_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("messages.id", ondelete="RESTRICT"), nullable=False
    )
    # Whose device this PKESK is for (recipient or the sender's own devices).
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    # Either a device key, or the account's recovery key (spec §6.2 item 3).
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("devices.id", ondelete="RESTRICT")
    )
    public_key_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("public_keys.id", ondelete="RESTRICT")
    )
    recovery_key_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("recovery_keys.id", ondelete="RESTRICT")
    )
    pkesk: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("message_id", "public_key_id"),
        UniqueConstraint("message_id", "recovery_key_id"),
        Index(None, "message_id", "device_id"),
        CheckConstraint(
            "(device_id IS NOT NULL AND public_key_id IS NOT NULL AND recovery_key_id IS NULL)"
            " OR (device_id IS NULL AND public_key_id IS NULL AND recovery_key_id IS NOT NULL)",
            name="one_target",
        ),
        CheckConstraint("length(pkesk) BETWEEN 1 AND 4096", name="pkesk_length"),
    )


class MailboxEntry(Base):
    __tablename__ = "mailbox_entries"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    message_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("messages.id", ondelete="RESTRICT"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    folder: Mapped[str] = mapped_column(String(16), nullable=False)
    folder_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("mail_folders.id", ondelete="RESTRICT")
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("message_id", "user_id"),
        CheckConstraint("folder IN ('inbox', 'sent', 'trash', 'custom')", name="folder_valid"),
        CheckConstraint("(folder = 'custom') = (folder_id IS NOT NULL)", name="custom_folder_id"),
        Index(None, "user_id", "folder", "created_at"),
        Index(None, "folder_id", "created_at"),
    )
