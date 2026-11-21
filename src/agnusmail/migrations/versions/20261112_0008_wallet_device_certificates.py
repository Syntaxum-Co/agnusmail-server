"""wallet-signed EIP-712 device certificates and revocations

Revision ID: 20261112_0008
Revises: 20261112_0007
Create Date: 2026-11-12

- devices: certificate_signature / certificate_issued_at / certificate_expires_at
  (EIP-712 DeviceCertificate) and wallet_revocation_signature / wallet_revoked_at
  (optional EIP-712 DeviceRevocation), each group set together.
- audit event type 'device.certificate_renewed'.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261112_0008"
down_revision: str | None = "20261112_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREVIOUS_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked', 'audit.purged', "
    "'auth.login', 'auth.login_denied', 'auth.logout', 'auth.session_revoked', "
    "'address.claimed'"
)
NEW_TYPES = PREVIOUS_TYPES + ", 'device.certificate_renewed'"
SIGNATURE_HEX = "^0x[0-9a-f]{130}$"


def _replace_event_check(types: str) -> None:
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"), "audit_events", f"event_type IN ({types})"
    )


def upgrade() -> None:
    op.add_column("devices", sa.Column("certificate_signature", sa.String(132), nullable=True))
    op.add_column(
        "devices", sa.Column("certificate_issued_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "devices", sa.Column("certificate_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "devices", sa.Column("wallet_revocation_signature", sa.String(132), nullable=True)
    )
    op.add_column(
        "devices", sa.Column("wallet_revoked_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_check_constraint(
        op.f("ck_devices_certificate_complete"),
        "devices",
        "(certificate_signature IS NULL) = (certificate_issued_at IS NULL) "
        "AND (certificate_signature IS NULL) = (certificate_expires_at IS NULL)",
    )
    op.create_check_constraint(
        op.f("ck_devices_wallet_revocation_complete"),
        "devices",
        "(wallet_revocation_signature IS NULL) = (wallet_revoked_at IS NULL)",
    )
    op.create_check_constraint(
        op.f("ck_devices_signatures_hex"),
        "devices",
        f"certificate_signature ~ '{SIGNATURE_HEX}' "
        f"AND wallet_revocation_signature ~ '{SIGNATURE_HEX}'",
    )
    _replace_event_check(NEW_TYPES)


def downgrade() -> None:
    if not context.is_offline_mode():
        count = op.get_bind().execute(
            sa.text(
                "SELECT count(*) FROM audit_events WHERE event_type = 'device.certificate_renewed'"
            )
        )
        if count.scalar_one():
            raise RuntimeError("irreversible: device.certificate_renewed events already exist")
    _replace_event_check(PREVIOUS_TYPES)
    for name in ("signatures_hex", "wallet_revocation_complete", "certificate_complete"):
        op.drop_constraint(op.f(f"ck_devices_{name}"), "devices", type_="check")
    for column in (
        "wallet_revoked_at",
        "wallet_revocation_signature",
        "certificate_expires_at",
        "certificate_issued_at",
        "certificate_signature",
    ):
        op.drop_column("devices", column)
