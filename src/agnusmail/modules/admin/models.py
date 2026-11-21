"""Administration: no web panel; a CLI on the server.

- ``operators``: wallet addresses allowed to act. Each command is signed in the
  operator's own wallet (EIP-191) and pasted into the CLI; the key never touches the
  server.
- ``admin_actions``: every command. Changes are requested by one operator and executed
  only when a **different** operator approves; metadata queries need one operator. No
  action reads or reveals message content (there is nothing to decrypt with).
- ``admin_signatures``: each signed message is used once (replay protection).

These tables belong to the admin database role only: the API's runtime role has no
access to them, so a compromised API cannot add operators.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, CheckConstraint, DateTime, Index, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

ADDRESS = r"^0x[0-9a-f]{40}$"


class OperatorStatus(StrEnum):
    ACTIVE = "active"
    REMOVED = "removed"


class ActionStatus(StrEnum):
    PENDING = "pending"  # waiting for a second operator
    EXECUTED = "executed"
    FAILED = "failed"  # approved, but the change could not be applied (reason recorded)
    EXPIRED = "expired"  # not approved in time


class Operator(Base):
    __tablename__ = "operators"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=OperatorStatus.ACTIVE)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("address"),
        CheckConstraint("status IN ('active', 'removed')", name="status_valid"),
        CheckConstraint(f"address ~ '{ADDRESS}'", name="address_format").ddl_if(
            dialect="postgresql"
        ),
    )


class AdminAction(Base):
    __tablename__ = "admin_actions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(42), nullable=False)  # operator or "bootstrap"
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(42))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'executed', 'failed', 'expired')", name="status_valid"
        ),
        CheckConstraint("approved_by IS NULL OR approved_by <> requested_by", name="two_operators"),
        Index(None, "status", "requested_at"),
    )


class AdminSignature(Base):
    __tablename__ = "admin_signatures"

    nonce: Mapped[str] = mapped_column(String(32), primary_key=True)
    operator: Mapped[str] = mapped_column(String(42), nullable=False)
    used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
