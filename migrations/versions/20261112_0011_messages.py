"""E2EE messages: body once, PKESK per device key, mailbox entries

Revision ID: 20261112_0011
Revises: 20261112_0010
Create Date: 2026-11-12

Ciphertext only (protocol v1 §6). Rows are never updated except the mailbox state.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261112_0011"
down_revision: str | None = "20261112_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "messages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sender_id", sa.Uuid(), nullable=False),
        sa.Column("client_message_id", sa.String(length=32), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "size = length(body) AND size > 0", name=op.f("ck_messages_size_matches_body")
        ),
        sa.CheckConstraint(
            "length(client_message_id) = 32", name=op.f("ck_messages_client_message_id_length")
        ),
        sa.CheckConstraint(
            "client_message_id ~ '^[0-9a-f]{32}$'", name=op.f("ck_messages_client_message_id_hex")
        ),
        sa.ForeignKeyConstraint(
            ["sender_id"],
            ["users.id"],
            name=op.f("fk_messages_sender_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_messages")),
        sa.UniqueConstraint(
            "sender_id", "client_message_id", name=op.f("uq_messages_sender_id_client_message_id")
        ),
    )
    op.create_table(
        "message_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("public_key_id", sa.Uuid(), nullable=False),
        sa.Column("pkesk", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(pkesk) BETWEEN 1 AND 4096", name=op.f("ck_message_keys_pkesk_length")
        ),
        sa.ForeignKeyConstraint(
            ["message_id"],
            ["messages.id"],
            name=op.f("fk_message_keys_message_id_messages"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_message_keys_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_message_keys_device_id_devices"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["public_key_id"],
            ["public_keys.id"],
            name=op.f("fk_message_keys_public_key_id_public_keys"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_message_keys")),
        sa.UniqueConstraint(
            "message_id", "public_key_id", name=op.f("uq_message_keys_message_id_public_key_id")
        ),
    )
    op.create_index(
        op.f("ix_message_keys_message_id_device_id"), "message_keys", ["message_id", "device_id"]
    )
    op.create_table(
        "mailbox_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("folder", sa.String(length=16), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "folder IN ('inbox', 'sent', 'trash')", name=op.f("ck_mailbox_entries_folder_valid")
        ),
        sa.ForeignKeyConstraint(
            ["message_id"],
            ["messages.id"],
            name=op.f("fk_mailbox_entries_message_id_messages"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mailbox_entries_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mailbox_entries")),
        sa.UniqueConstraint(
            "message_id", "user_id", name=op.f("uq_mailbox_entries_message_id_user_id")
        ),
    )
    op.create_index(
        op.f("ix_mailbox_entries_user_id_folder_created_at"),
        "mailbox_entries",
        ["user_id", "folder", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_mailbox_entries_user_id_folder_created_at"), table_name="mailbox_entries"
    )
    op.drop_table("mailbox_entries")
    op.drop_index(op.f("ix_message_keys_message_id_device_id"), table_name="message_keys")
    op.drop_table("message_keys")
    op.drop_table("messages")
