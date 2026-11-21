"""gateway signing keys: public certificates of the inbound gateway

Revision ID: 20261113_0015
Revises: 20261112_0014
Create Date: 2026-11-13

- gateway_keys: every certificate the gateway signed with (protocol v1 §9), kept so old
  external messages stay verifiable after a key rotation.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261113_0015"
down_revision: str | None = "20261112_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "gateway_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("material", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(material) BETWEEN 1 AND 16384", name=op.f("ck_gateway_keys_material_length")
        ),
        sa.CheckConstraint(
            "fingerprint ~ '^[0-9a-f]{64}$'", name=op.f("ck_gateway_keys_fingerprint_hex")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_gateway_keys")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_gateway_keys_fingerprint")),
    )


def downgrade() -> None:
    op.drop_table("gateway_keys")
