"""encrypted attachments in object storage

Revision ID: 20261112_0012
Revises: 20261112_0011
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261112_0012"
down_revision: str | None = "20261112_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attachments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("object_key", sa.String(length=80), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("message_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'uploaded', 'attached', 'deleted')",
            name=op.f("ck_attachments_status_valid"),
        ),
        sa.CheckConstraint("size > 0", name=op.f("ck_attachments_size_positive")),
        sa.CheckConstraint(
            "(status = 'attached') = (message_id IS NOT NULL)",
            name=op.f("ck_attachments_attached_has_message"),
        ),
        sa.CheckConstraint(
            "(status = 'deleted') = (deleted_at IS NOT NULL)",
            name=op.f("ck_attachments_deleted_timestamp"),
        ),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_attachments_sha256_hex")),
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["users.id"],
            name=op.f("fk_attachments_owner_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["message_id"],
            ["messages.id"],
            name=op.f("fk_attachments_message_id_messages"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attachments")),
        sa.UniqueConstraint("object_key", name=op.f("uq_attachments_object_key")),
    )
    op.create_index(op.f("ix_attachments_owner_id_status"), "attachments", ["owner_id", "status"])
    op.create_index(op.f("ix_attachments_message_id"), "attachments", ["message_id"])
    op.create_index(
        op.f("ix_attachments_status_created_at"), "attachments", ["status", "created_at"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_attachments_status_created_at"), table_name="attachments")
    op.drop_index(op.f("ix_attachments_message_id"), table_name="attachments")
    op.drop_index(op.f("ix_attachments_owner_id_status"), table_name="attachments")
    op.drop_table("attachments")
