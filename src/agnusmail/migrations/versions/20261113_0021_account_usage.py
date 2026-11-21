"""account usage: stored bytes per account, for the storage quota

Revision ID: 20261113_0021
Revises: 20261113_0020
Create Date: 2026-11-13

- account_usage: running counter of stored bytes (messages held, attachments uploaded,
  portal messages), filled here from the existing data.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261113_0021"
down_revision: str | None = "20261113_0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "account_usage",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("stored_bytes", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "stored_bytes >= 0", name=op.f("ck_account_usage_stored_bytes_positive")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_account_usage_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_account_usage")),
    )
    op.execute(
        """
        INSERT INTO account_usage (user_id, stored_bytes, updated_at)
        SELECT u.id, COALESCE(m.total, 0) + COALESCE(a.total, 0) + COALESCE(p.total, 0), now()
        FROM users u
        LEFT JOIN (
            SELECT e.user_id, sum(msg.size) AS total
            FROM mailbox_entries e JOIN messages msg ON msg.id = e.message_id
            GROUP BY e.user_id
        ) m ON m.user_id = u.id
        LEFT JOIN (
            SELECT owner_id, sum(size) AS total FROM attachments
            WHERE status IN ('uploaded', 'attached') GROUP BY owner_id
        ) a ON a.owner_id = u.id
        LEFT JOIN (
            SELECT sender_id, sum(size) AS total FROM portal_messages GROUP BY sender_id
        ) p ON p.sender_id = u.id
        """
    )


def downgrade() -> None:
    op.drop_table("account_usage")
