"""mail addresses name@domain bound to accounts

Revision ID: 20261112_0005
Revises: 20261111_0004
Create Date: 2026-11-12

- mail_addresses: one per account; canonical form unique per domain and never released
  (retired rows keep it). The local-part syntax is also enforced by a regex CHECK.
- audit event type 'address.claimed'.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261112_0005"
down_revision: str | None = "20261111_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged', "
    "'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked'"
)
NEW_TYPES = PREVIOUS_TYPES + ", 'address.claimed'"


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    op.create_table(
        "mail_addresses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("local_part", sa.String(length=32), nullable=False),
        sa.Column("canonical", sa.String(length=32), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'retired')", name=op.f("ck_mail_addresses_status_valid")
        ),
        sa.CheckConstraint(
            "length(local_part) BETWEEN 3 AND 32",
            name=op.f("ck_mail_addresses_local_part_length"),
        ),
        sa.CheckConstraint(
            "length(canonical) BETWEEN 1 AND 32",
            name=op.f("ck_mail_addresses_canonical_length"),
        ),
        sa.CheckConstraint(
            "local_part ~ '^[a-z0-9]([a-z0-9]|[._-][a-z0-9])*$'",
            name=op.f("ck_mail_addresses_local_part_syntax"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mail_addresses_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mail_addresses")),
        sa.UniqueConstraint("user_id", name=op.f("uq_mail_addresses_user_id")),
        sa.UniqueConstraint("domain", "canonical", name=op.f("uq_mail_addresses_domain_canonical")),
        sa.UniqueConstraint(
            "domain", "local_part", name=op.f("uq_mail_addresses_domain_local_part")
        ),
    )
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text("SELECT count(*) FROM audit_events WHERE event_type = 'address.claimed'")
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: address.claimed audit events already exist")
    _replace_event_check(PREVIOUS_TYPES)
    op.drop_table("mail_addresses")
