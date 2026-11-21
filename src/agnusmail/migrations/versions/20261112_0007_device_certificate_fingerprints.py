"""v6 fingerprints and expiry of device certificates

Revision ID: 20261112_0007
Revises: 20261112_0006
Create Date: 2026-11-12

- public_keys: fingerprint (primary), signing_fingerprint, encryption_fingerprint,
  expires_at. Nullable only for rows registered before this revision (interim opaque
  material); the application always fills them now.
- devices.fingerprint: primary-key fingerprint fixed by the device's first certificate,
  globally unique.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261112_0007"
down_revision: str | None = "20261112_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

HEX64 = "^[0-9a-f]{64}$"


def upgrade() -> None:
    for column in ("fingerprint", "signing_fingerprint", "encryption_fingerprint"):
        op.add_column("public_keys", sa.Column(column, sa.String(length=64), nullable=True))
    op.add_column("public_keys", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("devices", sa.Column("fingerprint", sa.String(length=64), nullable=True))
    op.create_unique_constraint(op.f("uq_devices_fingerprint"), "devices", ["fingerprint"])
    op.create_check_constraint(
        op.f("ck_devices_fingerprint_hex"), "devices", f"fingerprint ~ '{HEX64}'"
    )
    op.create_check_constraint(
        op.f("ck_public_keys_fingerprints_hex"),
        "public_keys",
        f"fingerprint ~ '{HEX64}' AND signing_fingerprint ~ '{HEX64}' "
        f"AND encryption_fingerprint ~ '{HEX64}'",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_public_keys_fingerprints_hex"), "public_keys", type_="check")
    op.drop_constraint(op.f("ck_devices_fingerprint_hex"), "devices", type_="check")
    op.drop_constraint(op.f("uq_devices_fingerprint"), "devices", type_="unique")
    op.drop_column("devices", "fingerprint")
    op.drop_column("public_keys", "expires_at")
    for column in ("encryption_fingerprint", "signing_fingerprint", "fingerprint"):
        op.drop_column("public_keys", column)
