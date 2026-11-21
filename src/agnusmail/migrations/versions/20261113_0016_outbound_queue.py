"""outbound queue: conventional SMTP delivery, not end-to-end encrypted

Revision ID: 20261113_0016
Revises: 20261113_0015
Create Date: 2026-11-13

- outbound_keys: public certificates of the outbound service's queue keys (spec §10).
- outbound_messages / outbound_recipients: the 72 h encrypted queue and
  per-recipient delivery state.
- messages.origin: also 'outbound' (the sender's own E2EE copy in Sent) and 'portal'
  (replies through the secure portal, spec §11; no sender account).
- audit event type 'outbound.submitted'.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261113_0016"
down_revision: str | None = "20261113_0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged', "
    "'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked', "
    "'address.claimed', 'device.certificate_renewed', 'auth.session_bound', "
    "'auth.passkey_registered', 'auth.passkey_revoked', "
    "'recovery.key_registered', 'recovery.backup_stored', 'recovery.migration_requested', "
    "'recovery.migration_cancelled', 'recovery.migration_completed'"
)
NEW_TYPES = PREVIOUS_TYPES + ", 'outbound.submitted'"
HEX64 = "^[0-9a-f]{64}$"


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def _replace_origin_checks(origins: str, with_sender: str) -> None:
    op.drop_constraint(op.f("ck_messages_origin_sender"), "messages", type_="check")
    op.drop_constraint(op.f("ck_messages_origin_valid"), "messages", type_="check")
    op.create_check_constraint(
        op.f("ck_messages_origin_valid"), "messages", f"origin IN ({origins})"
    )
    op.create_check_constraint(
        op.f("ck_messages_origin_sender"),
        "messages",
        f"(origin IN ({with_sender})) = (sender_id IS NOT NULL)",
    )


def upgrade() -> None:
    op.create_table(
        "outbound_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("encryption_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("material", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(material) BETWEEN 1 AND 16384", name=op.f("ck_outbound_keys_material_length")
        ),
        sa.CheckConstraint(
            f"fingerprint ~ '{HEX64}'", name=op.f("ck_outbound_keys_fingerprint_hex")
        ),
        sa.CheckConstraint(
            f"encryption_fingerprint ~ '{HEX64}'",
            name=op.f("ck_outbound_keys_encryption_fingerprint_hex"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbound_keys")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_outbound_keys_fingerprint")),
        sa.UniqueConstraint(
            "encryption_fingerprint", name=op.f("uq_outbound_keys_encryption_fingerprint")
        ),
    )
    op.create_table(
        "outbound_messages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("client_message_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("sender_address", sa.String(length=254), nullable=False),
        sa.Column("key_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'done', 'expired')",
            name=op.f("ck_outbound_messages_status_valid"),
        ),
        sa.CheckConstraint(
            "kind IN ('message', 'portal_notice')", name=op.f("ck_outbound_messages_kind_valid")
        ),
        sa.CheckConstraint(
            "(status = 'queued') = (payload IS NOT NULL)",
            name=op.f("ck_outbound_messages_payload_only_queued"),
        ),
        sa.CheckConstraint(
            "(status = 'queued') = (finished_at IS NULL)",
            name=op.f("ck_outbound_messages_finished_state"),
        ),
        sa.CheckConstraint(
            "payload IS NULL OR length(payload) = size",
            name=op.f("ck_outbound_messages_size_matches_payload"),
        ),
        sa.CheckConstraint("size > 0", name=op.f("ck_outbound_messages_size_positive")),
        sa.CheckConstraint(
            "expires_at <= created_at + interval '72 hours'",
            name=op.f("ck_outbound_messages_ttl_72h"),
        ),
        sa.CheckConstraint(
            "client_message_id ~ '^[0-9a-f]{32}$'",
            name=op.f("ck_outbound_messages_client_message_id_hex"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_outbound_messages_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbound_messages")),
        sa.UniqueConstraint(
            "user_id",
            "client_message_id",
            name=op.f("uq_outbound_messages_user_id_client_message_id"),
        ),
    )
    op.create_index(
        op.f("ix_outbound_messages_status_next_attempt_at"),
        "outbound_messages",
        ["status", "next_attempt_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_outbound_messages_user_id_created_at"),
        "outbound_messages",
        ["user_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "outbound_recipients",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("outbound_message_id", sa.Uuid(), nullable=False),
        sa.Column("address", sa.String(length=254), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("smtp_code", sa.Integer(), nullable=True),
        sa.Column("smtp_status", sa.String(length=32), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'delivered', 'failed')",
            name=op.f("ck_outbound_recipients_recipient_status_valid"),
        ),
        sa.CheckConstraint(
            "smtp_code IS NULL OR smtp_code BETWEEN 200 AND 599",
            name=op.f("ck_outbound_recipients_smtp_code"),
        ),
        sa.ForeignKeyConstraint(
            ["outbound_message_id"],
            ["outbound_messages.id"],
            name=op.f("fk_outbound_recipients_outbound_message_id_outbound_messages"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbound_recipients")),
        sa.UniqueConstraint(
            "outbound_message_id",
            "address",
            name=op.f("uq_outbound_recipients_outbound_message_id_address"),
        ),
    )
    _replace_origin_checks("'internal', 'external', 'outbound', 'portal'", "'internal', 'outbound'")
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text(
                "SELECT (SELECT count(*) FROM messages WHERE origin IN ('outbound', 'portal'))"
                " + (SELECT count(*) FROM audit_events WHERE event_type = 'outbound.submitted')"
                " + (SELECT count(*) FROM outbound_messages)"
            )
        )
        if count.scalar_one():
            # Never delete users' mail or history to make a downgrade pass.
            raise RuntimeError("irreversible: outbound data already exists")
    _replace_event_check(PREVIOUS_TYPES)
    _replace_origin_checks("'internal', 'external'", "'internal'")
    op.drop_table("outbound_recipients")
    op.drop_index(op.f("ix_outbound_messages_user_id_created_at"), table_name="outbound_messages")
    op.drop_index(
        op.f("ix_outbound_messages_status_next_attempt_at"), table_name="outbound_messages"
    )
    op.drop_table("outbound_messages")
    op.drop_table("outbound_keys")
