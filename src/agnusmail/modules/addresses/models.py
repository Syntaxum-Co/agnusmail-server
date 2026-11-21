"""E-mail addresses ``local_part@domain`` bound to accounts.

``canonical`` (punctuation removed, confusables unified) is unique per domain and is
never released: a ``retired`` or ``disabled`` row keeps it forever, so no one inherits
another person's address.

``kind``: each account has one ``primary`` address and up to ``MAX_ALIASES`` ``alias``
addresses. A disabled alias stops receiving (it no longer resolves)
and can be enabled again by its owner; its name is never given to anyone else.
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
from agnusmail.modules.addresses.rules import MAX_LENGTH

MAX_ALIASES = 5  # per account, disabled ones included (names are never released)


class AddressStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"  # aliases only: switched off by the owner, reversible
    RETIRED = "retired"


class AddressKind(StrEnum):
    PRIMARY = "primary"
    ALIAS = "alias"
    DOMAIN = "domain"  # on the owner's verified custom domain


class MailAddress(Base):
    __tablename__ = "mail_addresses"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    local_part: Mapped[str] = mapped_column(String(MAX_LENGTH), nullable=False)
    canonical: Mapped[str] = mapped_column(String(MAX_LENGTH), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=AddressStatus.ACTIVE)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default=AddressKind.PRIMARY)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        # One primary address per account; aliases are extra rows.
        Index(
            "uq_mail_addresses_primary_per_user",
            "user_id",
            unique=True,
            postgresql_where=text("kind = 'primary'"),
            sqlite_where=text("kind = 'primary'"),
        ),
        Index(None, "user_id"),
        CheckConstraint("kind IN ('primary', 'alias', 'domain')", name="kind_valid"),
        CheckConstraint(
            "status <> 'disabled' OR kind IN ('alias', 'domain')", name="only_aliases_disable"
        ),
        UniqueConstraint("domain", "canonical"),
        UniqueConstraint("domain", "local_part"),
        CheckConstraint("status IN ('active', 'disabled', 'retired')", name="status_valid"),
        CheckConstraint("length(local_part) BETWEEN 3 AND 32", name="local_part_length"),
        CheckConstraint("length(canonical) BETWEEN 1 AND 32", name="canonical_length"),
        # Same syntax as rules.LOCAL_PART; the regex operator is PostgreSQL-specific.
        CheckConstraint(
            "local_part ~ '^[a-z0-9]([a-z0-9]|[._-][a-z0-9])*$'", name="local_part_syntax"
        ).ddl_if(dialect="postgresql"),
    )

    @property
    def email(self) -> str:
        return f"{self.local_part}@{self.domain}"
