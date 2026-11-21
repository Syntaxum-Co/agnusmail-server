"""secure portal: password-encrypted messages for external recipients

Revision ID: 20261113_0017
Revises: 20261113_0016
Create Date: 2026-11-13

- portal_messages: the OpenPGP message (PKESKs + SKESK v6/Argon2 + SEIPDv2), at most
  30 days (spec §11).
- portal_links: one per recipient; only the SHA-256 of the link token.
- audit event types 'portal.created' and 'portal.deleted'.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261113_0017"
down_revision: str | None = "20261113_0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged', "
    "'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked', "
    "'address.claimed', 'device.certificate_renewed', 'auth.session_bound', "
    "'auth.passkey_registered', 'auth.passkey_revoked', "
    "'recovery.key_registered', 'recovery.backup_stored', 'recovery.migration_requested', "
    "'recovery.migration_cancelled', 'recovery.migration_completed', 'outbound.submitted'"
)
NEW_TYPES = PREVIOUS_TYPES + ", 'portal.created', 'portal.deleted'"


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    op.create_table(
        "portal_messages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sender_id", sa.Uuid(), nullable=False),
        sa.Column("client_message_id", sa.String(length=32), nullable=False),
        sa.Column("envelope", sa.LargeBinary(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "size = length(envelope) AND size > 0",
            name=op.f("ck_portal_messages_size_matches_envelope"),
        ),
        sa.CheckConstraint(
            "expires_at <= created_at + interval '30 days'",
            name=op.f("ck_portal_messages_ttl_30_days"),
        ),
        sa.CheckConstraint(
            "client_message_id ~ '^[0-9a-f]{32}$'",
            name=op.f("ck_portal_messages_client_message_id_hex"),
        ),
        sa.ForeignKeyConstraint(
            ["sender_id"],
            ["users.id"],
            name=op.f("fk_portal_messages_sender_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_portal_messages")),
        sa.UniqueConstraint(
            "sender_id",
            "client_message_id",
            name=op.f("uq_portal_messages_sender_id_client_message_id"),
        ),
    )
    op.create_index(
        op.f("ix_portal_messages_sender_id_created_at"),
        "portal_messages",
        ["sender_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_portal_messages_expires_at"), "portal_messages", ["expires_at"], unique=False
    )
    op.create_table(
        "portal_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("portal_message_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("recipient", sa.String(length=254), nullable=False),
        sa.Column("replies", sa.Integer(), nullable=False),
        sa.Column("last_access_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("replies BETWEEN 0 AND 100", name=op.f("ck_portal_links_replies_range")),
        sa.CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_portal_links_token_hash_hex")
        ),
        sa.ForeignKeyConstraint(
            ["portal_message_id"],
            ["portal_messages.id"],
            name=op.f("fk_portal_links_portal_message_id_portal_messages"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_portal_links")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_portal_links_token_hash")),
        sa.UniqueConstraint(
            "portal_message_id",
            "recipient",
            name=op.f("uq_portal_links_portal_message_id_recipient"),
        ),
    )
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text(
                "SELECT (SELECT count(*) FROM portal_messages)"
                " + (SELECT count(*) FROM audit_events WHERE left(event_type, 7) = 'portal.')"
            )
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: portal data already exists")
    _replace_event_check(PREVIOUS_TYPES)
    op.drop_table("portal_links")
    op.drop_index(op.f("ix_portal_messages_expires_at"), table_name="portal_messages")
    op.drop_index(op.f("ix_portal_messages_sender_id_created_at"), table_name="portal_messages")
    op.drop_table("portal_messages")
