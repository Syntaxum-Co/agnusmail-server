"""Identity persistence: users identified by their Ethereum address.

Holds no secrets: only the public address, account status and timestamps.
"""

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, String, UniqueConstraint, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

ADDRESS_LENGTH = 42  # "0x" + 40 hex chars


class UserStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Stored lowercase; uniqueness is therefore case-insensitive (EIP-55 is only a checksum).
    ethereum_address: Mapped[str] = mapped_column(String(ADDRESS_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=UserStatus.ACTIVE, server_default=UserStatus.ACTIVE
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("ethereum_address"),
        CheckConstraint("ethereum_address = lower(ethereum_address)", name="address_lowercase"),
        CheckConstraint(f"length(ethereum_address) = {ADDRESS_LENGTH}", name="address_length"),
        # Regex operator is PostgreSQL-specific; the portable checks above still apply elsewhere.
        CheckConstraint("ethereum_address ~ '^0x[0-9a-f]{40}$'", name="address_hex").ddl_if(
            dialect="postgresql"
        ),
        CheckConstraint("status IN ('active', 'suspended')", name="status_valid"),
    )
