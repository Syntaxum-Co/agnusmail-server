"""audit event types for authentication (login, logout, session revocation)

Revision ID: 20261111_0004
Revises: 20261111_0003
Create Date: 2026-11-11

Only widens the event_type CHECK constraint (DV-05).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261111_0004"
down_revision: str | None = "20261111_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged'"
)
NEW_TYPES = PREVIOUS_TYPES + (
    ", 'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked'"
)


def _replace_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    _replace_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text("SELECT count(*) FROM audit_events WHERE left(event_type, 5) = 'auth.'")
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: authentication audit events already exist")
    _replace_check(PREVIOUS_TYPES)
