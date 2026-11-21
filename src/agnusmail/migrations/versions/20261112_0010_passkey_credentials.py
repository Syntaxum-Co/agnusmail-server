"""passkey (WebAuthn) credentials approved by the wallet

Revision ID: 20261112_0010
Revises: 20261112_0009
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261112_0010"
down_revision: str | None = "20261112_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged', "
    "'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked', "
    "'address.claimed', 'device.certificate_renewed', 'auth.session_bound'"
)
NEW_TYPES = PREVIOUS_TYPES + ", 'auth.passkey_registered', 'auth.passkey_revoked'"


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    op.create_table(
        "passkey_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("backed_up", sa.Boolean(), nullable=False),
        sa.Column("aaguid", sa.String(length=36), nullable=False),
        sa.Column("wallet_signature", sa.String(length=132), nullable=False),
        sa.Column("wallet_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name=op.f("ck_passkey_credentials_status_valid")
        ),
        sa.CheckConstraint(
            "(status = 'revoked') = (revoked_at IS NOT NULL)",
            name=op.f("ck_passkey_credentials_revoked_timestamp"),
        ),
        sa.CheckConstraint(
            "length(credential_id) BETWEEN 1 AND 1023",
            name=op.f("ck_passkey_credentials_credential_id_length"),
        ),
        sa.CheckConstraint(
            "sign_count >= 0", name=op.f("ck_passkey_credentials_sign_count_non_negative")
        ),
        sa.CheckConstraint(
            "length(name) BETWEEN 1 AND 64", name=op.f("ck_passkey_credentials_name_length")
        ),
        sa.CheckConstraint(
            "wallet_signature ~ '^0x[0-9a-f]{130}$'",
            name=op.f("ck_passkey_credentials_wallet_signature_hex"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_passkey_credentials_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_passkey_credentials")),
        sa.UniqueConstraint("credential_id", name=op.f("uq_passkey_credentials_credential_id")),
    )
    op.create_index(
        op.f("ix_passkey_credentials_user_id_status"),
        "passkey_credentials",
        ["user_id", "status"],
    )
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text(
                "SELECT count(*) FROM audit_events "
                "WHERE event_type IN ('auth.passkey_registered', 'auth.passkey_revoked')"
            )
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: passkey audit events already exist")
    _replace_event_check(PREVIOUS_TYPES)
    op.drop_index(op.f("ix_passkey_credentials_user_id_status"), table_name="passkey_credentials")
    op.drop_table("passkey_credentials")
