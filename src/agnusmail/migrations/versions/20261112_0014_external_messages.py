"""external messages: received by the inbound SMTP gateway

Revision ID: 20261112_0014
Revises: 20261112_0013
Create Date: 2026-11-12

- messages.origin: 'internal' (E2EE from an Agnusmail sender) or 'external' (encrypted on
  arrival by the gateway, protocol v1 §9). External messages have no sender account.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261112_0014"
down_revision: str | None = "20261112_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "messages",
        sa.Column("origin", sa.String(length=16), nullable=False, server_default="internal"),
    )
    op.alter_column("messages", "origin", server_default=None)
    op.alter_column("messages", "sender_id", existing_type=sa.Uuid(), nullable=True)
    op.create_check_constraint(
        op.f("ck_messages_origin_valid"), "messages", "origin IN ('internal', 'external')"
    )
    op.create_check_constraint(
        op.f("ck_messages_origin_sender"),
        "messages",
        "(origin = 'internal') = (sender_id IS NOT NULL)",
    )


def downgrade() -> None:
    if not context.is_offline_mode():
        external = op.get_bind().scalar(
            sa.text("SELECT count(*) FROM messages WHERE origin = 'external'")
        )
        if external:
            # Never delete users' mail to make a downgrade pass.
            raise RuntimeError("irreversible: external messages already exist")
    op.drop_constraint(op.f("ck_messages_origin_sender"), "messages", type_="check")
    op.drop_constraint(op.f("ck_messages_origin_valid"), "messages", type_="check")
    op.alter_column("messages", "sender_id", existing_type=sa.Uuid(), nullable=False)
    op.drop_column("messages", "origin")
