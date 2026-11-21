"""audit event type 'auth.session_bound' (4.D.5)

Revision ID: 20261112_0009
Revises: 20261112_0008
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261112_0009"
down_revision: str | None = "20261112_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged', "
    "'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked', "
    "'address.claimed', 'device.certificate_renewed'"
)
NEW_TYPES = PREVIOUS_TYPES + ", 'auth.session_bound'"


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text("SELECT count(*) FROM audit_events WHERE event_type = 'auth.session_bound'")
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: auth.session_bound events already exist")
    _replace_event_check(PREVIOUS_TYPES)
