"""Custom domains.

A user proves control of a domain with a TXT record; once verified, the gateways accept
it (inbound: its addresses resolve; outbound: its addresses can send, signed with
``d=<domain>`` through a CNAME to our DKIM key). A domain belongs to whoever controls
its DNS: a newer, verified claim by another account takes it over when the previous
owner's TXT record is gone.
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
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

MAX_DOMAINS = 3  # per account, any status
MAX_DOMAIN_ADDRESSES = 20  # per domain
VERIFICATION_PREFIX = "agnusmail-verification="
VERIFICATION_LABEL = "_agnusmail"


class DomainStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"


class MailDomain(Base):
    __tablename__ = "mail_domains"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=DomainStatus.PENDING)
    token: Mapped[str] = mapped_column(String(32), nullable=False)  # public: goes in DNS
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("user_id", "name"),
        # At most one account holds a domain as verified.
        Index(
            "uq_mail_domains_verified_name",
            "name",
            unique=True,
            postgresql_where=text("status = 'verified'"),
            sqlite_where=text("status = 'verified'"),
        ),
        CheckConstraint("status IN ('pending', 'verified')", name="status_valid"),
        CheckConstraint("(status = 'verified') = (verified_at IS NOT NULL)", name="verified_at"),
        CheckConstraint("token ~ '^[0-9a-f]{32}$'", name="token_hex").ddl_if(dialect="postgresql"),
    )

    @property
    def verification_host(self) -> str:
        return f"{VERIFICATION_LABEL}.{self.name}"

    @property
    def verification_value(self) -> str:
        return f"{VERIFICATION_PREFIX}{self.token}"
