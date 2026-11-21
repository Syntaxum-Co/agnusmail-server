"""Devices of a user. A device holds its own key pairs; the server only sees public keys.

Lifecycle: ``pending`` (registered, not trusted yet) → ``active`` (authorized) →
``revoked`` (terminal). A pending device may also be revoked (rejected).
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

DEVICE_NAME_MAX_LENGTH = 64
REVOCATION_REASON_MAX_LENGTH = 200


class DeviceStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(DEVICE_NAME_MAX_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=DeviceStatus.PENDING,
        server_default=DeviceStatus.PENDING,
    )
    # Application clock (microseconds) for stable ordering; server default for raw inserts.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
    )
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(REVOCATION_REASON_MAX_LENGTH))
    # v6 fingerprint of the device's primary key, fixed by its first certificate (4.D.2).
    # Globally unique: one certificate cannot stand for two devices.
    fingerprint: Mapped[str | None] = mapped_column(String(64), unique=True)
    # EIP-712 DeviceCertificate signed by the account's wallet (4.D.4): published with the
    # keys so senders can verify it themselves. Hex "0x" + 65 bytes.
    certificate_signature: Mapped[str | None] = mapped_column(String(132))
    certificate_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    certificate_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Optional EIP-712 DeviceRevocation signed by the wallet (spec §4.3 item 5).
    wallet_revocation_signature: Mapped[str | None] = mapped_column(String(132))
    wallet_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        # Target of the composite FK from public_keys: a key can only reference a device
        # of the same user (ownership enforced by the database, not only by the API).
        UniqueConstraint("id", "user_id"),
        CheckConstraint("status IN ('pending', 'active', 'revoked')", name="status_valid"),
        CheckConstraint(
            "status <> 'active' OR authorized_at IS NOT NULL", name="active_authorized"
        ),
        # The three certificate fields are set together (or not at all).
        CheckConstraint(
            "(certificate_signature IS NULL) = (certificate_issued_at IS NULL) "
            "AND (certificate_signature IS NULL) = (certificate_expires_at IS NULL)",
            name="certificate_complete",
        ),
        CheckConstraint(
            "(wallet_revocation_signature IS NULL) = (wallet_revoked_at IS NULL)",
            name="wallet_revocation_complete",
        ),
        CheckConstraint(
            "(status = 'revoked') = (revoked_at IS NOT NULL)", name="revoked_timestamp"
        ),
        CheckConstraint(f"length(name) BETWEEN 1 AND {DEVICE_NAME_MAX_LENGTH}", name="name_length"),
        CheckConstraint("fingerprint ~ '^[0-9a-f]{64}$'", name="fingerprint_hex").ddl_if(
            dialect="postgresql"
        ),
        CheckConstraint(
            "certificate_signature ~ '^0x[0-9a-f]{130}$' "
            "AND wallet_revocation_signature ~ '^0x[0-9a-f]{130}$'",
            name="signatures_hex",
        ).ddl_if(dialect="postgresql"),
        Index(None, "user_id", "status"),
    )
