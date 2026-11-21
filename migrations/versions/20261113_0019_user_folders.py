"""user folders with client-encrypted names

Revision ID: 20261113_0019
Revises: 20261113_0018
Create Date: 2026-11-13

- mail_folders: the name is an OpenPGP message only the owner's devices open.
- mailbox_entries.folder: also 'custom', with folder_id.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261113_0019"
down_revision: str | None = "20261113_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _replace_folder_check(values: str) -> None:
    op.drop_constraint(op.f("ck_mailbox_entries_folder_valid"), "mailbox_entries", type_="check")
    op.create_check_constraint(
        op.f("ck_mailbox_entries_folder_valid"), "mailbox_entries", f"folder IN ({values})"
    )


def upgrade() -> None:
    op.create_table(
        "mail_folders",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(name) BETWEEN 1 AND 4096", name=op.f("ck_mail_folders_name_length")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mail_folders_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mail_folders")),
    )
    op.create_index(
        op.f("ix_mail_folders_user_id_created_at"), "mail_folders", ["user_id", "created_at"]
    )
    op.add_column("mailbox_entries", sa.Column("folder_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_mailbox_entries_folder_id_mail_folders"),
        "mailbox_entries",
        "mail_folders",
        ["folder_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        op.f("ix_mailbox_entries_folder_id_created_at"),
        "mailbox_entries",
        ["folder_id", "created_at"],
    )
    _replace_folder_check("'inbox', 'sent', 'trash', 'custom'")
    op.create_check_constraint(
        op.f("ck_mailbox_entries_custom_folder_id"),
        "mailbox_entries",
        "(folder = 'custom') = (folder_id IS NOT NULL)",
    )


def downgrade() -> None:
    if not context.is_offline_mode():
        folders = op.get_bind().scalar(sa.text("SELECT count(*) FROM mail_folders"))
        if folders:
            raise RuntimeError("irreversible: user folders already exist")
    op.drop_constraint(
        op.f("ck_mailbox_entries_custom_folder_id"), "mailbox_entries", type_="check"
    )
    _replace_folder_check("'inbox', 'sent', 'trash'")
    op.drop_index(op.f("ix_mailbox_entries_folder_id_created_at"), table_name="mailbox_entries")
    op.drop_constraint(
        op.f("fk_mailbox_entries_folder_id_mail_folders"), "mailbox_entries", type_="foreignkey"
    )
    op.drop_column("mailbox_entries", "folder_id")
    op.drop_index(op.f("ix_mail_folders_user_id_created_at"), table_name="mail_folders")
    op.drop_table("mail_folders")
