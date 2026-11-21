"""address aliases: up to 5 extra addresses per account, can be disabled

Revision ID: 20261113_0018
Revises: 20261113_0017
Create Date: 2026-11-13

- mail_addresses.kind: 'primary' (one per account) or 'alias'; status 'disabled' for
  aliases switched off by their owner.
- audit event types 'address.alias_claimed', 'address.disabled', 'address.enabled'.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261113_0018"
down_revision: str | None = "20261113_0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged', "
    "'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked', "
    "'address.claimed', 'device.certificate_renewed', 'auth.session_bound', "
    "'auth.passkey_registered', 'auth.passkey_revoked', "
    "'recovery.key_registered', 'recovery.backup_stored', 'recovery.migration_requested', "
    "'recovery.migration_cancelled', 'recovery.migration_completed', 'outbound.submitted', "
    "'portal.created', 'portal.deleted'"
)
NEW_TYPES = PREVIOUS_TYPES + (", 'address.alias_claimed', 'address.disabled', 'address.enabled'")


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def _replace_status_check(statuses: str) -> None:
    op.drop_constraint(op.f("ck_mail_addresses_status_valid"), "mail_addresses", type_="check")
    op.create_check_constraint(
        op.f("ck_mail_addresses_status_valid"), "mail_addresses", f"status IN ({statuses})"
    )


def upgrade() -> None:
    op.add_column(
        "mail_addresses",
        sa.Column("kind", sa.String(length=16), nullable=False, server_default="primary"),
    )
    op.alter_column("mail_addresses", "kind", server_default=None)
    op.drop_constraint(op.f("uq_mail_addresses_user_id"), "mail_addresses", type_="unique")
    op.create_index(
        "uq_mail_addresses_primary_per_user",
        "mail_addresses",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("kind = 'primary'"),
    )
    op.create_index(op.f("ix_mail_addresses_user_id"), "mail_addresses", ["user_id"])
    op.create_check_constraint(
        op.f("ck_mail_addresses_kind_valid"), "mail_addresses", "kind IN ('primary', 'alias')"
    )
    op.create_check_constraint(
        op.f("ck_mail_addresses_only_aliases_disable"),
        "mail_addresses",
        "status <> 'disabled' OR kind = 'alias'",
    )
    _replace_status_check("'active', 'disabled', 'retired'")
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        aliases = op.get_bind().scalar(
            sa.text("SELECT count(*) FROM mail_addresses WHERE kind = 'alias'")
        )
        if aliases:
            raise RuntimeError("irreversible: aliases already exist")
    _replace_event_check(PREVIOUS_TYPES)
    _replace_status_check("'active', 'retired'")
    op.drop_constraint(
        op.f("ck_mail_addresses_only_aliases_disable"), "mail_addresses", type_="check"
    )
    op.drop_constraint(op.f("ck_mail_addresses_kind_valid"), "mail_addresses", type_="check")
    op.drop_index(op.f("ix_mail_addresses_user_id"), table_name="mail_addresses")
    op.drop_index("uq_mail_addresses_primary_per_user", table_name="mail_addresses")
    op.create_unique_constraint(op.f("uq_mail_addresses_user_id"), "mail_addresses", ["user_id"])
    op.drop_column("mail_addresses", "kind")
