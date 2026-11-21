"""Audit trail of device and key changes.

Append-only: the PostgreSQL migration installs a trigger that rejects UPDATE and
TRUNCATE, and DELETE except the controlled retention purge. ``id`` is a global
sequence; ``chain_seq`` orders the events of one user and each event stores the hash of
the previous one (``chain.py``), so rewriting or dropping events is detectable.

``details`` holds only non-secret metadata (states, versions, formats, content digests,
hashed client fingerprint). Never key material, tokens or message content.
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base


class AuditEventType(StrEnum):
    DEVICE_REGISTERED = "device.registered"
    DEVICE_AUTHORIZED = "device.authorized"
    DEVICE_REVOKED = "device.revoked"
    DEVICE_CERTIFICATE_RENEWED = "device.certificate_renewed"
    KEY_REGISTERED = "key.registered"
    KEY_SUPERSEDED = "key.superseded"
    KEY_REVOKED = "key.revoked"
    AUDIT_PURGED = "audit.purged"
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_DENIED = "auth.login_denied"
    AUTH_LOGOUT = "auth.logout"
    AUTH_SESSION_REVOKED = "auth.session_revoked"
    AUTH_SESSION_BOUND = "auth.session_bound"
    AUTH_PASSKEY_REGISTERED = "auth.passkey_registered"
    AUTH_PASSKEY_REVOKED = "auth.passkey_revoked"
    RECOVERY_KEY_REGISTERED = "recovery.key_registered"
    RECOVERY_BACKUP_STORED = "recovery.backup_stored"
    RECOVERY_MIGRATION_REQUESTED = "recovery.migration_requested"
    RECOVERY_MIGRATION_CANCELLED = "recovery.migration_cancelled"
    RECOVERY_MIGRATION_COMPLETED = "recovery.migration_completed"
    ADDRESS_CLAIMED = "address.claimed"
    ADDRESS_ALIAS_CLAIMED = "address.alias_claimed"
    ADDRESS_DISABLED = "address.disabled"
    ADDRESS_ENABLED = "address.enabled"
    ADDRESS_DOMAIN_CLAIMED = "address.domain_claimed"
    DOMAIN_ADDED = "domain.added"
    DOMAIN_VERIFIED = "domain.verified"
    DOMAIN_REMOVED = "domain.removed"
    DOMAIN_LOST = "domain.lost"
    ABUSE_REPORTED = "abuse.reported"
    ABUSE_RESTRICTED = "abuse.restricted"
    ADMIN_SUSPENDED = "admin.suspended"
    ADMIN_REINSTATED = "admin.reinstated"
    ADMIN_RESTRICTION_LIFTED = "admin.restriction_lifted"
    OUTBOUND_SUBMITTED = "outbound.submitted"
    PORTAL_CREATED = "portal.created"
    PORTAL_DELETED = "portal.deleted"


EVENT_TYPES_SQL = ", ".join(f"'{event.value}'" for event in AuditEventType)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    # BIGINT sequence in PostgreSQL; INTEGER (rowid alias) in SQLite so it autoincrements.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    # Whose resources changed (the history is shown to this user).
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    # Who performed the change; NULL means the system.
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT")
    )
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("devices.id", ondelete="RESTRICT")
    )
    public_key_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("public_keys.id", ondelete="RESTRICT")
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False, default=dict
    )
    # Set by the application (it is part of the hash), never by the database clock.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # Per-user position in the chain (1, 2, 3, ...) and the SHA-256 links.
    chain_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    event_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    __table_args__ = (
        CheckConstraint(f"event_type IN ({EVENT_TYPES_SQL})", name="event_type_valid"),
        CheckConstraint("chain_seq >= 1", name="chain_seq_positive"),
        CheckConstraint("length(prev_hash) = 32", name="prev_hash_length"),
        CheckConstraint("length(event_hash) = 32", name="event_hash_length"),
        UniqueConstraint("user_id", "chain_seq"),
        Index(None, "user_id", "id"),
        Index(None, "device_id", "id"),
    )


class AuditChainHead(Base):
    """Tip and purge checkpoint of one user's chain.

    The row is locked (``SELECT ... FOR UPDATE``) by every append, which serializes the
    chain of a user. ``purged_through_*`` is where verification restarts after the
    retention purge deleted the events up to that sequence.
    """

    __tablename__ = "audit_chain_heads"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    head_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    head_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    purged_through_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    purged_through_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("purged_through_seq >= 0", name="purged_through_seq_non_negative"),
        CheckConstraint("head_seq >= purged_through_seq", name="head_after_checkpoint"),
        CheckConstraint("length(head_hash) = 32", name="head_hash_length"),
        CheckConstraint("length(purged_through_hash) = 32", name="purged_through_hash_length"),
    )
