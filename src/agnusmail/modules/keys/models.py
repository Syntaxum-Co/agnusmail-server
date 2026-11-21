"""Public key directory storage.

Each row is a version of a device's OpenPGP v6 certificate (protocol v1 §3): validated on
registration (structure, fingerprints, expiry, proof of possession — ``policy.py``) and
then stored as the exact bytes the client sent. ``material_digest`` ("sha256:<hex>") is
a content digest for integrity and de-duplication; the protocol identifier is the v6
fingerprint of the primary key (``fingerprint``).

Versioning: every certificate registered for a device gets the next version number and
supersedes the previous active one. All versions of a device share the same primary key.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

KEY_FORMAT_MAX_LENGTH = 64
KEY_FORMAT_PATTERN = r"^[a-z0-9][a-z0-9._/+-]{0,63}$"
MATERIAL_HARD_LIMIT_BYTES = 16384  # schema bound; the configured API limit is lower
DIGEST_PREFIX = "sha256:"
DIGEST_LENGTH = len(DIGEST_PREFIX) + 64
FINGERPRINT_LENGTH = 64  # OpenPGP v6 fingerprint (SHA-256), lowercase hex


class PublicKeyStatus(StrEnum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


class PublicKey(Base):
    __tablename__ = "public_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # Opaque format label chosen by the client; the protocol defines the allowed values
    # (docs/specs/protocol-v1.md).
    format: Mapped[str] = mapped_column(String(KEY_FORMAT_MAX_LENGTH), nullable=False)
    material: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    material_digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=PublicKeyStatus.ACTIVE,
        server_default=PublicKeyStatus.ACTIVE,
    )
    # Application clock (microseconds) for stable ordering; server default for raw inserts.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
    )
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Protocol v1: v6 fingerprints (lowercase hex) of the primary key and of the
    # signing and encryption subkeys, plus the certificate's expiry. NULL only on rows
    # registered before migration 0007 (interim opaque material).
    fingerprint: Mapped[str | None] = mapped_column(String(FINGERPRINT_LENGTH))
    signing_fingerprint: Mapped[str | None] = mapped_column(String(FINGERPRINT_LENGTH))
    encryption_fingerprint: Mapped[str | None] = mapped_column(String(FINGERPRINT_LENGTH))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        # The key's owner must be the device's owner (enforced by the database).
        ForeignKeyConstraint(
            ["device_id", "user_id"], ["devices.id", "devices.user_id"], ondelete="RESTRICT"
        ),
        UniqueConstraint("device_id", "version"),
        # Per-user uniqueness only: global uniqueness would let anyone "squat" a public
        # key they saw (they are public) and block its owner. The proof of possession
        # (bound to the account) and devices.fingerprint stop binding someone else's key.
        UniqueConstraint("user_id", "material_digest"),
        # At most one active key per (device, format).
        Index(
            None,
            "device_id",
            "format",
            unique=True,
            postgresql_where=text("status = 'active'"),
            sqlite_where=text("status = 'active'"),
        ),
        Index(None, "user_id", "status"),
        CheckConstraint("status IN ('active', 'superseded', 'revoked')", name="status_valid"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint(
            f"length(material) BETWEEN 1 AND {MATERIAL_HARD_LIMIT_BYTES}", name="material_length"
        ),
        CheckConstraint(
            f"length(material_digest) = {DIGEST_LENGTH} "
            f"AND substr(material_digest, 1, {len(DIGEST_PREFIX)}) = '{DIGEST_PREFIX}'",
            name="material_digest_format",
        ),
        CheckConstraint(
            "(status = 'revoked') = (revoked_at IS NOT NULL)", name="revoked_timestamp"
        ),
        CheckConstraint(
            "status <> 'superseded' OR superseded_at IS NOT NULL", name="superseded_timestamp"
        ),
        CheckConstraint(f"format ~ '{KEY_FORMAT_PATTERN}'", name="format_label").ddl_if(
            dialect="postgresql"
        ),
        CheckConstraint(
            "fingerprint ~ '^[0-9a-f]{64}$' AND signing_fingerprint ~ '^[0-9a-f]{64}$' "
            "AND encryption_fingerprint ~ '^[0-9a-f]{64}$'",
            name="fingerprints_hex",
        ).ddl_if(dialect="postgresql"),
    )
