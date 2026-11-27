"""secure portal: view-once links

Revision ID: 20261127_0028
Revises: 20261121_0027
Create Date: 2026-11-27

- portal_messages.view_seconds: how long a link stays readable after its first access
  (60 s to 1 h); null keeps the link readable until the message expires.
- portal_links.viewable_until: set by that first access.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261127_0028"
down_revision: str | None = "20261121_0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("portal_messages", sa.Column("view_seconds", sa.Integer(), nullable=True))
    op.create_check_constraint(
        op.f("ck_portal_messages_view_seconds_range"),
        "portal_messages",
        "view_seconds IS NULL OR view_seconds BETWEEN 60 AND 3600",
    )
    op.add_column(
        "portal_links",
        sa.Column("viewable_until", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("portal_links", "viewable_until")
    op.drop_constraint(
        op.f("ck_portal_messages_view_seconds_range"), "portal_messages", type_="check"
    )
    op.drop_column("portal_messages", "view_seconds")
