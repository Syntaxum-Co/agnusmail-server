"""account recovery: recovery keys, encrypted backups, wallet migrations

Revision ID: 20261112_0013
Revises: 20261112_0012
Create Date: 2026-11-12

- recovery_keys, recovery_backups, account_migrations (protocol v1 §8).
- message_keys: a PKESK may target the account's recovery key instead of a device key.
- audit event types for recovery.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261112_0013"
down_revision: str | None = "20261112_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged', "
    "'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked', "
    "'address.claimed', 'device.certificate_renewed', 'auth.session_bound', "
    "'auth.passkey_registered', 'auth.passkey_revoked'"
)
NEW_TYPES = PREVIOUS_TYPES + (
    ", 'recovery.key_registered', 'recovery.backup_stored', 'recovery.migration_requested', "
    "'recovery.migration_cancelled', 'recovery.migration_completed'"
)
HEX64 = "^[0-9a-f]{64}$"


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    op.create_table(
        "recovery_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("material", sa.LargeBinary(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("signing_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("encryption_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("wallet_account", sa.String(length=42), nullable=False),
        sa.Column("wallet_signature", sa.String(length=132), nullable=False),
        sa.Column("wallet_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("replaced_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'replaced')", name=op.f("ck_recovery_keys_status_valid")
        ),
        sa.CheckConstraint(
            "(status = 'replaced') = (replaced_at IS NOT NULL)",
            name=op.f("ck_recovery_keys_replaced_timestamp"),
        ),
        sa.CheckConstraint(
            "length(material) BETWEEN 1 AND 16384", name=op.f("ck_recovery_keys_material_length")
        ),
        sa.CheckConstraint(
            f"fingerprint ~ '{HEX64}' AND signing_fingerprint ~ '{HEX64}' "
            f"AND encryption_fingerprint ~ '{HEX64}'",
            name=op.f("ck_recovery_keys_fingerprints_hex"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_recovery_keys_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recovery_keys")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_recovery_keys_fingerprint")),
    )
    op.create_index(
        op.f("ix_recovery_keys_user_id"),
        "recovery_keys",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_table(
        "recovery_backups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("recovery_key_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("version >= 1", name=op.f("ck_recovery_backups_version_positive")),
        sa.CheckConstraint(
            "length(blob) BETWEEN 1 AND 65536", name=op.f("ck_recovery_backups_blob_length")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_recovery_backups_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["recovery_key_id"],
            ["recovery_keys.id"],
            name=op.f("fk_recovery_backups_recovery_key_id_recovery_keys"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recovery_backups")),
        sa.UniqueConstraint("user_id", "version", name=op.f("uq_recovery_backups_user_id_version")),
    )
    op.create_table(
        "account_migrations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("recovery_key_id", sa.Uuid(), nullable=False),
        sa.Column("old_account", sa.String(length=42), nullable=False),
        sa.Column("new_account", sa.String(length=42), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recovery_signature", sa.LargeBinary(), nullable=False),
        sa.Column("acceptance_signature", sa.String(length=132), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'cancelled', 'completed')",
            name=op.f("ck_account_migrations_status_valid"),
        ),
        sa.CheckConstraint(
            "(status = 'pending') = (finished_at IS NULL)",
            name=op.f("ck_account_migrations_finished_timestamp"),
        ),
        sa.CheckConstraint(
            "effective_at > requested_at", name=op.f("ck_account_migrations_waiting_period")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_account_migrations_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["recovery_key_id"],
            ["recovery_keys.id"],
            name=op.f("fk_account_migrations_recovery_key_id_recovery_keys"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_account_migrations")),
    )
    op.create_index(
        op.f("ix_account_migrations_user_id"),
        "account_migrations",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        op.f("ix_account_migrations_status_effective_at"),
        "account_migrations",
        ["status", "effective_at"],
    )

    # message_keys: device key OR recovery key.
    op.add_column("message_keys", sa.Column("recovery_key_id", sa.Uuid(), nullable=True))
    op.alter_column("message_keys", "device_id", nullable=True)
    op.alter_column("message_keys", "public_key_id", nullable=True)
    op.create_foreign_key(
        op.f("fk_message_keys_recovery_key_id_recovery_keys"),
        "message_keys",
        "recovery_keys",
        ["recovery_key_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_unique_constraint(
        op.f("uq_message_keys_message_id_recovery_key_id"),
        "message_keys",
        ["message_id", "recovery_key_id"],
    )
    op.create_check_constraint(
        op.f("ck_message_keys_one_target"),
        "message_keys",
        "(device_id IS NOT NULL AND public_key_id IS NOT NULL AND recovery_key_id IS NULL)"
        " OR (device_id IS NULL AND public_key_id IS NULL AND recovery_key_id IS NOT NULL)",
    )
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text(
                "SELECT (SELECT count(*) FROM audit_events WHERE left(event_type, 9) = 'recovery.')"
                " + (SELECT count(*) FROM message_keys WHERE recovery_key_id IS NOT NULL)"
            )
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: recovery data already exists")
    _replace_event_check(PREVIOUS_TYPES)
    op.drop_constraint(op.f("ck_message_keys_one_target"), "message_keys", type_="check")
    op.drop_constraint(
        op.f("uq_message_keys_message_id_recovery_key_id"), "message_keys", type_="unique"
    )
    op.drop_constraint(
        op.f("fk_message_keys_recovery_key_id_recovery_keys"), "message_keys", type_="foreignkey"
    )
    op.alter_column("message_keys", "public_key_id", nullable=False)
    op.alter_column("message_keys", "device_id", nullable=False)
    op.drop_column("message_keys", "recovery_key_id")
    op.drop_index(
        op.f("ix_account_migrations_status_effective_at"), table_name="account_migrations"
    )
    op.drop_index(op.f("ix_account_migrations_user_id"), table_name="account_migrations")
    op.drop_table("account_migrations")
    op.drop_table("recovery_backups")
    op.drop_index(op.f("ix_recovery_keys_user_id"), table_name="recovery_keys")
    op.drop_table("recovery_keys")
