"""abuse reports (metadata only) and account restrictions

Revision ID: 20261113_0024
Revises: 20261113_0021
Create Date: 2026-11-13

- abuse_reports: which message, which sender, which category, who reported. No content.
- account_restrictions: temporary restriction after reports or bounces.
- audit event types 'abuse.reported' and 'abuse.restricted'.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261113_0024"
down_revision: str | None = "20261113_0021"
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
    "'domain.lost'"
)
NEW_TYPES = PREVIOUS_TYPES + ", 'abuse.reported', 'abuse.restricted'"


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    op.create_table(
        "abuse_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.Uuid(), nullable=False),
        sa.Column("reporter_id", sa.Uuid(), nullable=False),
        sa.Column("reported_id", sa.Uuid(), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "category IN ('spam', 'phishing', 'harassment', 'malware', 'other')",
            name=op.f("ck_abuse_reports_category_valid"),
        ),
        sa.CheckConstraint("reporter_id <> reported_id", name=op.f("ck_abuse_reports_not_self")),
        sa.ForeignKeyConstraint(
            ["reporter_id"],
            ["users.id"],
            name=op.f("fk_abuse_reports_reporter_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["reported_id"],
            ["users.id"],
            name=op.f("fk_abuse_reports_reported_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_abuse_reports")),
        sa.UniqueConstraint(
            "message_id", "reporter_id", name=op.f("uq_abuse_reports_message_id_reporter_id")
        ),
    )
    op.create_index(
        op.f("ix_abuse_reports_reported_id_created_at"),
        "abuse_reports",
        ["reported_id", "created_at"],
    )
    op.create_table(
        "account_restrictions",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("reason", sa.String(length=16), nullable=False),
        sa.Column("restricted_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "reason IN ('reports', 'bounces')", name=op.f("ck_account_restrictions_reason_valid")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_account_restrictions_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_account_restrictions")),
    )
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text(
                "SELECT (SELECT count(*) FROM abuse_reports)"
                " + (SELECT count(*) FROM account_restrictions)"
            )
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: abuse records already exist")
    _replace_event_check(PREVIOUS_TYPES)
    op.drop_table("account_restrictions")
    op.drop_index(op.f("ix_abuse_reports_reported_id_created_at"), table_name="abuse_reports")
    op.drop_table("abuse_reports")
