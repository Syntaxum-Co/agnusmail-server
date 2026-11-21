"""administration: operators, two-operator actions, single-use signatures

Revision ID: 20261116_0026
Revises: 20261113_0024
Create Date: 2026-11-16

- operators, admin_actions, admin_signatures (admin role only; see roles.py).
- audit event types 'admin.suspended', 'admin.reinstated', 'admin.restriction_lifted',
  'admin.period_granted'.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261116_0026"
down_revision: str | None = "20261113_0024"
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
    "'portal.created', 'portal.deleted', "
    "'address.alias_claimed', 'address.disabled', 'address.enabled', "
    "'address.domain_claimed', 'domain.added', 'domain.verified', 'domain.removed', "
    "'domain.lost', 'abuse.reported', 'abuse.restricted'"
)
NEW_TYPES = PREVIOUS_TYPES + (", 'admin.suspended', 'admin.reinstated', 'admin.restriction_lifted'")


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    op.create_table(
        "operators",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("address", sa.String(length=42), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'removed')", name=op.f("ck_operators_status_valid")
        ),
        sa.CheckConstraint(
            "address ~ '^0x[0-9a-f]{40}$'", name=op.f("ck_operators_address_format")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_operators")),
        sa.UniqueConstraint("address", name=op.f("uq_operators_address")),
    )
    op.create_table(
        "admin_actions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("requested_by", sa.String(length=42), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(length=42), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'executed', 'failed', 'expired')",
            name=op.f("ck_admin_actions_status_valid"),
        ),
        sa.CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name=op.f("ck_admin_actions_two_operators"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_actions")),
    )
    op.create_index(
        op.f("ix_admin_actions_status_requested_at"),
        "admin_actions",
        ["status", "requested_at"],
    )
    op.create_table(
        "admin_signatures",
        sa.Column("nonce", sa.String(length=32), nullable=False),
        sa.Column("operator", sa.String(length=42), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("nonce", name=op.f("pk_admin_signatures")),
    )
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        if op.get_bind().scalar(sa.text("SELECT count(*) FROM admin_actions")):
            raise RuntimeError("irreversible: administrative actions already exist")
    _replace_event_check(PREVIOUS_TYPES)
    op.drop_table("admin_signatures")
    op.drop_index(op.f("ix_admin_actions_status_requested_at"), table_name="admin_actions")
    op.drop_table("admin_actions")
    op.drop_table("operators")
