"""Passkey (WebAuthn) credentials of an account.

Only public data: the credential id, its COSE public key, the signature counter and
metadata. Each credential was approved by the account's wallet (EIP-712
``PasskeyRegistration``); the signature is kept as evidence. Rows are never deleted
(revocation is a status), so the audit trail always resolves.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

PASSKEY_NAME_MAX_LENGTH = 64
CREDENTIAL_ID_MAX_BYTES = 1023  # WebAuthn Level 3 limit


class PasskeyStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # COSE_Key
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    name: Mapped[str] = mapped_column(String(PASSKEY_NAME_MAX_LENGTH), nullable=False)
    # Synced ("multi-device") passkey vs bound to one authenticator.
    backed_up: Mapped[bool] = mapped_column(Boolean, nullable=False)
    aaguid: Mapped[str] = mapped_column(String(36), nullable=False)
    # EIP-712 PasskeyRegistration signed by the account's wallet.
    wallet_signature: Mapped[str] = mapped_column(String(132), nullable=False)
    wallet_issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=PasskeyStatus.ACTIVE)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("credential_id"),
        CheckConstraint("status IN ('active', 'revoked')", name="status_valid"),
        CheckConstraint(
            "(status = 'revoked') = (revoked_at IS NOT NULL)", name="revoked_timestamp"
        ),
        CheckConstraint(
            f"length(credential_id) BETWEEN 1 AND {CREDENTIAL_ID_MAX_BYTES}",
            name="credential_id_length",
        ),
        CheckConstraint("sign_count >= 0", name="sign_count_non_negative"),
        CheckConstraint(
            f"length(name) BETWEEN 1 AND {PASSKEY_NAME_MAX_LENGTH}", name="name_length"
        ),
        CheckConstraint(
            "wallet_signature ~ '^0x[0-9a-f]{130}$'", name="wallet_signature_hex"
        ).ddl_if(dialect="postgresql"),
        Index(None, "user_id", "status"),
    )
