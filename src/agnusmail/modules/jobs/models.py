"""Durable job queue in PostgreSQL.

Jobs carry only parameters (ids, counters), never message content or secrets: the
payload keys are allowlisted per job kind and the size is capped. A job is claimed with a
lease (``locked_until``); a worker that dies leaves the lease to expire and another
worker takes the job again, so handlers must be idempotent.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from agnusmail.infrastructure.database.base import Base

MAX_PAYLOAD_BYTES = 2048


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    DEAD = "dead"  # gave up after max_attempts


class Job(Base):
    __tablename__ = "jobs"

    # BIGINT sequence in PostgreSQL; INTEGER (rowid alias) in SQLite so it autoincrements.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False, default=dict
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=JobStatus.QUEUED)
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    locked_by: Mapped[str | None] = mapped_column(String(128))
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Exception class name only: messages could carry data.
    last_error: Mapped[str | None] = mapped_column(String(128))
    # Periodic jobs use "periodic:<kind>:<period>" so several workers never duplicate them.
    dedupe_key: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'dead')", name="status_valid"
        ),
        CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        CheckConstraint("max_attempts BETWEEN 1 AND 50", name="max_attempts_range"),
        CheckConstraint(
            "status <> 'running' OR (locked_by IS NOT NULL AND locked_until IS NOT NULL)",
            name="running_has_lease",
        ),
        CheckConstraint(
            f"octet_length(CAST(payload AS text)) <= {MAX_PAYLOAD_BYTES}", name="payload_size"
        ).ddl_if(dialect="postgresql"),
        UniqueConstraint("dedupe_key"),
        Index(None, "status", "run_at"),
    )
