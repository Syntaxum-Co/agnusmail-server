"""Account recovery (protocol v1 §8).

- ``recovery_keys``: the account's recovery certificate (a "virtual device" that never
  comes online), attested by the wallet. One active per account; replaced, never deleted.
- ``recovery_backups``: the recovery secret key, encrypted on the client with the
  24-word phrase (SKESK v6 Argon2 + SEIPDv2). The server stores it and never decrypts.
- ``account_migrations``: moving the account to a new wallet after losing the old one,
  with a 7-day waiting period during which the owner can cancel.
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
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

MAX_BACKUP_BYTES = 64 * 1024


class RecoveryKeyStatus(StrEnum):
    ACTIVE = "active"
    REPLACED = "replaced"


class RecoveryKey(Base):
    __tablename__ = "recovery_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    material: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # EIP-712 RecoveryKeyCertificate signed by the wallet that owned the account then.
    wallet_account: Mapped[str] = mapped_column(String(42), nullable=False)
    wallet_signature: Mapped[str] = mapped_column(String(132), nullable=False)
    wallet_issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=RecoveryKeyStatus.ACTIVE
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    replaced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("fingerprint"),
        CheckConstraint("status IN ('active', 'replaced')", name="status_valid"),
        CheckConstraint(
            "(status = 'replaced') = (replaced_at IS NOT NULL)", name="replaced_timestamp"
        ),
        CheckConstraint("length(material) BETWEEN 1 AND 16384", name="material_length"),
        # One active recovery key per account.
        Index(
            None,
            "user_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
            sqlite_where=text("status = 'active'"),
        ),
    )


class RecoveryBackup(Base):
    __tablename__ = "recovery_backups"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    recovery_key_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("recovery_keys.id", ondelete="RESTRICT"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("user_id", "version"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint(f"length(blob) BETWEEN 1 AND {MAX_BACKUP_BYTES}", name="blob_length"),
    )


class MigrationStatus(StrEnum):
    PENDING = "pending"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


class AccountMigration(Base):
    __tablename__ = "account_migrations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    recovery_key_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("recovery_keys.id", ondelete="RESTRICT"), nullable=False
    )
    old_account: Mapped[str] = mapped_column(String(42), nullable=False)
    new_account: Mapped[str] = mapped_column(String(42), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Proofs (public evidence after completion, spec §8.5 step 3).
    recovery_signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    acceptance_signature: Mapped[str] = mapped_column(String(132), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=MigrationStatus.PENDING)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("status IN ('pending', 'cancelled', 'completed')", name="status_valid"),
        CheckConstraint("(status = 'pending') = (finished_at IS NULL)", name="finished_timestamp"),
        CheckConstraint("effective_at > requested_at", name="waiting_period"),
        # At most one pending migration per account.
        Index(
            None,
            "user_id",
            unique=True,
            postgresql_where=text("status = 'pending'"),
            sqlite_where=text("status = 'pending'"),
        ),
        Index(None, "status", "effective_at"),
    )
