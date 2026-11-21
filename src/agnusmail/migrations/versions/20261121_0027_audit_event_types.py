"""audit event types as rows of a table, so extensions can add their own

Revision ID: 20261121_0027
Revises: 20261116_0026
Create Date: 2026-11-21

The CHECK constraint that listed every event type is replaced by a foreign key to
``audit_event_types``. Later migrations, here or in an extension, add types with one
INSERT instead of rewriting the whole list. Unknown types are still refused by the
database.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261121_0027"
down_revision: str | None = "20261116_0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Every type allowed by the CHECK constraint of 20261116_0026.
TYPES = (
    "device.registered",
    "device.authorized",
    "device.revoked",
    "key.registered",
    "key.superseded",
    "key.revoked",
    "audit.purged",
    "auth.login",
    "auth.login_denied",
    "auth.logout",
    "auth.session_revoked",
    "address.claimed",
    "device.certificate_renewed",
    "auth.session_bound",
    "auth.passkey_registered",
    "auth.passkey_revoked",
    "recovery.key_registered",
    "recovery.backup_stored",
    "recovery.migration_requested",
    "recovery.migration_cancelled",
    "recovery.migration_completed",
    "outbound.submitted",
    "portal.created",
    "portal.deleted",
    "address.alias_claimed",
    "address.disabled",
    "address.enabled",
    "address.domain_claimed",
    "domain.added",
    "domain.verified",
    "domain.removed",
    "domain.lost",
    "abuse.reported",
    "abuse.restricted",
    "admin.suspended",
    "admin.reinstated",
    "admin.restriction_lifted",
)


def upgrade() -> None:
    table = op.create_table(
        "audit_event_types",
        sa.Column("name", sa.String(length=48), nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_audit_event_types")),
    )
    op.bulk_insert(table, [{"name": name} for name in TYPES])
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_foreign_key(
        op.f("fk_audit_events_event_type_audit_event_types"),
        "audit_events",
        "audit_event_types",
        ["event_type"],
        ["name"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_audit_events_event_type_audit_event_types"), "audit_events", type_="foreignkey"
    )
    listed = ", ".join(f"'{name}'" for name in TYPES)
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({listed})"
    )
    op.drop_table("audit_event_types")
