"""create users

Revision ID: 20261110_0001
Revises:
Create Date: 2026-11-10

Users are identified by their Ethereum address (stored lowercase, unique).
No secrets are stored: only the public address, status and timestamps.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261110_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ethereum_address", sa.String(length=42), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "ethereum_address = lower(ethereum_address)",
            name=op.f("ck_users_address_lowercase"),
        ),
        sa.CheckConstraint("length(ethereum_address) = 42", name=op.f("ck_users_address_length")),
        sa.CheckConstraint(
            "ethereum_address ~ '^0x[0-9a-f]{40}$'", name=op.f("ck_users_address_hex")
        ),
        sa.CheckConstraint("status IN ('active', 'suspended')", name=op.f("ck_users_status_valid")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("ethereum_address", name=op.f("uq_users_ethereum_address")),
    )


def downgrade() -> None:
    op.drop_table("users")
