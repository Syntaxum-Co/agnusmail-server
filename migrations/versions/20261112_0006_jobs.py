"""durable job queue for the background worker

Revision ID: 20261112_0006
Revises: 20261112_0005
Create Date: 2026-11-12

Jobs carry parameters only (payload capped at 2048 bytes; keys allowlisted per kind in
the application), never message content or secrets.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261112_0006"
down_revision: str | None = "20261112_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_by", sa.String(length=128), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=128), nullable=True),
        sa.Column("dedupe_key", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'dead')",
            name=op.f("ck_jobs_status_valid"),
        ),
        sa.CheckConstraint("attempts >= 0", name=op.f("ck_jobs_attempts_non_negative")),
        sa.CheckConstraint(
            "max_attempts BETWEEN 1 AND 50", name=op.f("ck_jobs_max_attempts_range")
        ),
        sa.CheckConstraint(
            "status <> 'running' OR (locked_by IS NOT NULL AND locked_until IS NOT NULL)",
            name=op.f("ck_jobs_running_has_lease"),
        ),
        sa.CheckConstraint(
            "octet_length(CAST(payload AS text)) <= 2048", name=op.f("ck_jobs_payload_size")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
        sa.UniqueConstraint("dedupe_key", name=op.f("uq_jobs_dedupe_key")),
    )
    op.create_index(op.f("ix_jobs_status_run_at"), "jobs", ["status", "run_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_jobs_status_run_at"), table_name="jobs")
    op.drop_table("jobs")
