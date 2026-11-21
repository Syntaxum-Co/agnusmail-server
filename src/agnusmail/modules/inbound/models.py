"""Public certificates of the inbound gateway's signing keys (protocol v1 §9).

Kept forever (never updated or deleted) so that clients can verify the gateway
signature of old external messages after the key is rotated. Only public material.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import CheckConstraint, DateTime, LargeBinary, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base


class GatewayKey(Base):
    __tablename__ = "gateway_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    material: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("fingerprint"),
        CheckConstraint("length(material) BETWEEN 1 AND 16384", name="material_length"),
        CheckConstraint("fingerprint ~ '^[0-9a-f]{64}$'", name="fingerprint_hex").ddl_if(
            dialect="postgresql"
        ),
    )
