"""custom domains verified by TXT, with their own addresses

Revision ID: 20261113_0020
Revises: 20261113_0019
Create Date: 2026-11-13

- mail_domains: owner, name, status, verification token; one verified holder per name.
- mail_addresses.kind: also 'domain'. Only 'domain' addresses can ever be deleted (the
  domain was removed or changed hands): a trigger refuses deleting any other row, so
  names on the service's domain stay never-reused.
- audit event types for domains.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261113_0020"
down_revision: str | None = "20261113_0019"
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
    "'address.alias_claimed', 'address.disabled', 'address.enabled'"
)
NEW_TYPES = PREVIOUS_TYPES + (
    ", 'address.domain_claimed', 'domain.added', 'domain.verified', 'domain.removed', 'domain.lost'"
)


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def _replace_address_checks(kinds: str, disable: str) -> None:
    op.drop_constraint(op.f("ck_mail_addresses_kind_valid"), "mail_addresses", type_="check")
    op.drop_constraint(
        op.f("ck_mail_addresses_only_aliases_disable"), "mail_addresses", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_mail_addresses_kind_valid"), "mail_addresses", f"kind IN ({kinds})"
    )
    op.create_check_constraint(
        op.f("ck_mail_addresses_only_aliases_disable"),
        "mail_addresses",
        f"status <> 'disabled' OR kind IN ({disable})",
    )


def upgrade() -> None:
    op.create_table(
        "mail_domains",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("token", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'verified')", name=op.f("ck_mail_domains_status_valid")
        ),
        sa.CheckConstraint(
            "(status = 'verified') = (verified_at IS NOT NULL)",
            name=op.f("ck_mail_domains_verified_at"),
        ),
        sa.CheckConstraint("token ~ '^[0-9a-f]{32}$'", name=op.f("ck_mail_domains_token_hex")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mail_domains_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mail_domains")),
        sa.UniqueConstraint("user_id", "name", name=op.f("uq_mail_domains_user_id_name")),
    )
    op.create_index(
        "uq_mail_domains_verified_name",
        "mail_domains",
        ["name"],
        unique=True,
        postgresql_where=sa.text("status = 'verified'"),
    )
    _replace_address_checks("'primary', 'alias', 'domain'", "'alias', 'domain'")
    op.execute(
        """
        CREATE FUNCTION mail_addresses_guard_delete() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.kind <> 'domain' THEN
                RAISE EXCEPTION 'addresses on the service domain are never deleted'
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN OLD;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER mail_addresses_guard_delete BEFORE DELETE ON mail_addresses "
        "FOR EACH ROW EXECUTE FUNCTION mail_addresses_guard_delete()"
    )
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text(
                "SELECT (SELECT count(*) FROM mail_domains)"
                " + (SELECT count(*) FROM mail_addresses WHERE kind = 'domain')"
            )
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: custom domains already exist")
    _replace_event_check(PREVIOUS_TYPES)
    op.execute("DROP TRIGGER mail_addresses_guard_delete ON mail_addresses")
    op.execute("DROP FUNCTION mail_addresses_guard_delete()")
    _replace_address_checks("'primary', 'alias'", "'alias'")
    op.drop_index("uq_mail_domains_verified_name", table_name="mail_domains")
    op.drop_table("mail_domains")
